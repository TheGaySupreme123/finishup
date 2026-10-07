"""Issue #977: check-time requested-output gap codes reach the AI-powered reviewer packet.

Three seams carry the codes: ``check._semantic_evaluation`` -> ``Application.evaluate_semantic_check``
-> the evaluator (which unions them into ``captured_content_gaps`` -> packet ``known_gaps``).
Each forwarding step passes the keyword only to a callee that declares it.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any, cast

import pytest

from unit.application.test_semantic_case import (
    _build,  # pyright: ignore[reportPrivateUsage]
    _case_with_material,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.application.check import (
    _semantic_evaluation,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.application.service import Application
from yoetz.domain.privacy import ReviewContextProfile
from yoetz.kernel.deterministic_checks import REQUESTED_OUTPUT_ABSENT_FACT
from yoetz.kernel.task_facts import (
    REQUESTED_OUTPUT_GIT_IGNORED_GAP,
    REQUESTED_OUTPUT_UNVERIFIED_GAP,
)
from yoetz.ports.diagnostics import RuntimeCapability

pytestmark = pytest.mark.anyio

_GAPS = (REQUESTED_OUTPUT_ABSENT_FACT, REQUESTED_OUTPUT_GIT_IGNORED_GAP)


async def _call_facade(evaluator: object, **kwargs: object) -> None:
    holder = SimpleNamespace(semantic_evaluator=evaluator)
    await Application.evaluate_semantic_check(
        cast(Any, holder), cast(Any, object()), (), None, None, **cast(Any, kwargs)
    )


async def test_facade_forwards_task_fact_gaps_to_a_declaring_evaluator() -> None:
    seen: list[object] = []

    async def evaluator(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
        task_fact_gaps: tuple[str, ...] = (),
    ) -> object:
        del frozen, findings, runtime, lineage_evaluation, require_complete_specification
        seen.append(task_fact_gaps)
        return object()

    await _call_facade(evaluator, task_fact_gaps=_GAPS)
    assert seen == [_GAPS]


async def test_facade_does_not_pass_task_fact_gaps_to_an_evaluator_without_the_parameter() -> None:
    calls: list[dict[str, object]] = []

    async def legacy(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
    ) -> object:
        del frozen, findings, runtime, lineage_evaluation
        calls.append({"spec": require_complete_specification})
        return object()

    await _call_facade(legacy, task_fact_gaps=_GAPS)
    # One call only: the keyword was withheld up front, not discovered through the TypeError
    # fallback ladder (which would have re-called without require_complete_specification).
    assert calls == [{"spec": False}]


async def test_facade_omits_empty_task_fact_gaps() -> None:
    seen: list[tuple[str, ...]] = []

    async def evaluator(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
        task_fact_gaps: tuple[str, ...] = ("sentinel",),
    ) -> object:
        del frozen, findings, runtime, lineage_evaluation, require_complete_specification
        seen.append(task_fact_gaps)
        return object()

    await _call_facade(evaluator)
    assert seen == [("sentinel",)]


def _check_inputs() -> tuple[Any, Any]:
    request = SimpleNamespace(
        mode="semantic_if_configured", final_review=False, request_id="req_test"
    )
    runtime = SimpleNamespace(capabilities=frozenset({RuntimeCapability.SEMANTIC}))
    return request, runtime


async def _drive_check_seam(*, declares: bool, gaps: tuple[str, ...]) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    async def declaring(
        frozen: object,
        deterministic: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
        final_review: bool = False,
        task_fact_gaps: tuple[str, ...] = (),
    ) -> object:
        del frozen, deterministic, runtime, lineage_evaluation, final_review
        calls.append({"spec": require_complete_specification, "task_fact_gaps": task_fact_gaps})
        return object()

    async def legacy(
        frozen: object,
        deterministic: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        require_complete_specification: bool = False,
    ) -> object:
        del frozen, deterministic, runtime, lineage_evaluation
        calls.append({"spec": require_complete_specification})
        return object()

    seam: Callable[..., Awaitable[object]] = declaring if declares else legacy
    assert ("task_fact_gaps" in inspect.signature(seam).parameters) is declares
    app = SimpleNamespace(evaluate_semantic_check=seam)
    request, runtime = _check_inputs()
    await _semantic_evaluation(
        cast(Any, app),
        request,
        runtime,
        cast(Any, object()),
        (),
        route_profile="policy",
        task_fact_gaps=gaps,
    )
    return calls


async def test_check_forwards_nonempty_task_fact_gaps_when_the_seam_declares_them() -> None:
    assert await _drive_check_seam(declares=True, gaps=_GAPS) == [
        {"spec": False, "task_fact_gaps": _GAPS}
    ]


async def test_check_withholds_task_fact_gaps_from_a_seam_that_does_not_declare_them() -> None:
    assert await _drive_check_seam(declares=False, gaps=_GAPS) == [{"spec": False}]


async def test_check_does_not_pass_the_keyword_when_gaps_are_empty() -> None:
    received: list[set[str]] = []

    async def seam(
        frozen: object,
        deterministic: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
        **kwargs: object,
    ) -> object:
        del frozen, deterministic, runtime, lineage_evaluation
        received.append(set(kwargs))
        return object()

    request, runtime = _check_inputs()
    app = SimpleNamespace(evaluate_semantic_check=seam)
    for gaps in ((), (REQUESTED_OUTPUT_UNVERIFIED_GAP,)):
        await _semantic_evaluation(
            cast(Any, app),
            request,
            runtime,
            cast(Any, object()),
            (),
            route_profile="policy",
            task_fact_gaps=gaps,
        )
    assert "task_fact_gaps" not in received[0]
    assert "task_fact_gaps" in received[1]


def test_task_fact_gap_codes_reach_packet_known_gaps() -> None:
    gaps = tuple(sorted((*_GAPS, REQUESTED_OUTPUT_UNVERIFIED_GAP), key=str.encode))
    semantic = _build(
        _case_with_material(), ReviewContextProfile.EXPANDED, captured_content_gaps=gaps
    )

    assert set(gaps) <= set(semantic.packet.coverage.known_gaps)
    clean = _build(_case_with_material(), ReviewContextProfile.EXPANDED)
    assert not set(gaps) & set(clean.packet.coverage.known_gaps)


async def test_a_round_stopped_after_one_retry_never_calls_the_reviewer() -> None:
    """tb4n1 D3: after two insufficient-packet reviews in a row, the check skips the reviewer."""

    from yoetz.protocol.models import SemanticStatus

    calls: list[object] = []

    async def seam(*args: object, **kwargs: object) -> object:
        calls.append(args)
        return object()

    request, runtime = _check_inputs()
    result = await _semantic_evaluation(
        cast(Any, SimpleNamespace(evaluate_semantic_check=seam)),
        request,
        runtime,
        cast(Any, object()),
        (),
        route_profile="policy",
        round_stopped=True,
    )
    assert calls == []
    assert result.status is SemanticStatus.NOT_REQUESTED
