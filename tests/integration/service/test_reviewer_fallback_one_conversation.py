"""#1118 R3: a configured fallback under the one-conversation rule, through the real composition.

The real evaluator and privacy coordinator run over a durable SQLite job; only the provider behind
the gateway is scripted. A healthy primary reviews alone, an unresolved primary is served by the
fallback before anything is dispatched, and a primary that fails once its conversation may have
disclosed anything never starts a second conversation on the fallback.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from builders.privacy_policies import minimal_external_policy
from builders.privacy_widenings import with_llm
from finishup.ports.semantic import SemanticResultTimeout
from finishup.protocol.models import SemanticStatus
from integration.service import test_reviewer_conversation_composition as c
from integration.service import test_semantic_fallback_dispatch as f

pytestmark = pytest.mark.anyio

_FALLBACK = f._FALLBACK  # pyright: ignore[reportPrivateUsage]


def _timed_out(_case: object, provenance: Any) -> SemanticResultTimeout:
    return SemanticResultTimeout(replace(provenance, status=SemanticStatus.TIMEOUT))


def _paired_policy() -> Any:
    return with_llm(minimal_external_policy(), fallback_provider_binding=_FALLBACK)


async def _fallback() -> Any:
    return _FALLBACK


async def test_a_healthy_primary_reviews_with_a_fallback_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, gateway, _ = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        c._FINAL,  # pyright: ignore[reportPrivateUsage]
        policy=_paired_policy(),
        resolve_fallback=_fallback,
        configured_primary=c._BINDING,  # pyright: ignore[reportPrivateUsage]
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    assert gateway.bindings == [c._BINDING]  # pyright: ignore[reportPrivateUsage]


async def test_an_unresolved_primary_is_reviewed_by_the_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, gateway, _ = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        c._FINAL,  # pyright: ignore[reportPrivateUsage]
        policy=_paired_policy(),
        primary=None,
        resolve_fallback=_fallback,
        configured_primary=c._BINDING,  # pyright: ignore[reportPrivateUsage]
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    assert gateway.bindings == [_FALLBACK]
    assert result.provenance is not None and result.provenance.fallback_from is not None
    assert result.provenance.fallback_from.attempted_count == 0


async def test_a_primary_failing_after_disclosure_starts_no_second_conversation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, gateway, _ = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        c._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
        _timed_out,  # a licensing failure once the first exchange was sent
        policy=_paired_policy(),
        resolve_fallback=_fallback,
        configured_primary=c._BINDING,  # pyright: ignore[reportPrivateUsage]
    )
    assert gateway.bindings == [c._BINDING, c._BINDING]  # pyright: ignore[reportPrivateUsage]
    assert result.status is SemanticStatus.TIMEOUT and result.judgment is None
