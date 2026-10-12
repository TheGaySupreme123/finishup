"""Per-check semantic budget profile selection and freezing (issue #571)."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from builders.policy_cases import clm, make_case, record
from yoetz.domain.events import ClaimKind, ClaimRecordedPayload
from yoetz.domain.privacy import ProviderBinding
from yoetz.kernel.projections import empty_projection_state
from yoetz.ports.semantic_budget import (
    current_semantic_budget_profile,
    parse_semantic_budget_profile,
    select_semantic_budget_profile,
    semantic_budget_profile_scope,
)
from yoetz.service import ready_composition


def _claim(kind: ClaimKind, number: int) -> ClaimRecordedPayload:
    return ClaimRecordedPayload(clm(number), kind, "Statement", (), obligation_refs=())


def test_checks_without_a_completion_claim_are_routine() -> None:
    assert select_semantic_budget_profile(empty_projection_state()) == "routine"
    material = make_case(claims={clm(1): record(_claim(ClaimKind.MATERIAL, 1), 1)})
    assert select_semantic_budget_profile(material.projection) == "routine"


def test_an_effective_completion_claim_selects_the_final_profile() -> None:
    case = make_case(
        claims={
            clm(1): record(_claim(ClaimKind.MATERIAL, 1), 1),
            clm(2): record(_claim(ClaimKind.COMPLETION, 2), 2),
        }
    )
    assert select_semantic_budget_profile(case.projection) == "final"


def test_superseded_or_unreadable_completion_claims_do_not_select_final() -> None:
    superseded = replace(record(_claim(ClaimKind.COMPLETION, 1), 1), superseded_by_claim_id=clm(2))
    replacement = record(_claim(ClaimKind.MATERIAL, 2), 2)
    corrected = make_case(claims={clm(1): superseded, clm(2): replacement})
    assert select_semantic_budget_profile(corrected.projection) == "routine"

    redacted = replace(record(_claim(ClaimKind.COMPLETION, 1), 1), payload=None, redacted=True)
    unreadable = make_case(claims={clm(1): redacted})
    assert select_semantic_budget_profile(unreadable.projection) == "routine"


def test_dispatch_scope_exposes_the_profile_and_restores_the_legacy_default() -> None:
    assert current_semantic_budget_profile() == "final"
    with semantic_budget_profile_scope("routine"):
        assert current_semantic_budget_profile() == "routine"

        async def child() -> str:
            return current_semantic_budget_profile()

        # A task spawned inside the dispatch inherits the frozen profile.
        assert asyncio.run(child()) == "routine"
    assert current_semantic_budget_profile() == "final"
    with pytest.raises(ValueError, match="semantic_budget_profile_invalid"):
        parse_semantic_budget_profile("checkpoint")


def _execution(**overrides: object) -> object:
    binding = ProviderBinding(
        "openai-codex", "gpt-5.6-luna", "codex-chatgpt-subscription", "1.0.0", "external"
    )
    moment = datetime(2026, 9, 22, tzinfo=UTC)
    execution = ready_composition._SemanticExecution(  # pyright: ignore[reportPrivateUsage]
        binding, None, None, 2, moment, moment, 900.0
    )
    return replace(execution, **overrides)


def test_execution_snapshot_freezes_the_budget_profile_and_reads_legacy_snapshots() -> None:
    to_json = ready_composition._execution_json  # pyright: ignore[reportPrivateUsage]
    from_json = ready_composition._execution_from_json  # pyright: ignore[reportPrivateUsage]

    routine = _execution(budget_profile="routine")
    encoded = to_json(routine)  # pyright: ignore[reportArgumentType]
    assert encoded["budget_profile"] == "routine"
    assert from_json(encoded) == routine

    legacy = dict(encoded)
    del legacy["budget_profile"]
    assert from_json(legacy).budget_profile == "final"

    legacy["budget_profile"] = "checkpoint"
    with pytest.raises(ValueError, match="semantic_execution_invalid"):
        from_json(legacy)


def test_a_closing_review_request_selects_final_without_a_completion_claim() -> None:
    """TB4 tb4f1 (issue #976): an agent that never claims completion still gets the final phase.

    atrx-vep-crispr ran two routine reviews ("this review does not assess completion") while the
    requested report was never written, because only a completion claim selected ``final``.
    """

    empty = empty_projection_state()
    assert select_semantic_budget_profile(empty, final_review=True) == "final"
    material = make_case(claims={clm(1): record(_claim(ClaimKind.MATERIAL, 1), 1)})
    assert select_semantic_budget_profile(material.projection, final_review=True) == "final"
    # With a claim the request changes nothing; without either it stays routine.
    claimed = make_case(claims={clm(2): record(_claim(ClaimKind.COMPLETION, 2), 2)})
    assert select_semantic_budget_profile(claimed.projection, final_review=True) == "final"
    assert select_semantic_budget_profile(material.projection, final_review=False) == "routine"
    with pytest.raises(TypeError):
        select_semantic_budget_profile(empty, final_review=1)  # type: ignore[arg-type]
