"""Issue #855: an unresolved Codex runtime records its exact structural refusal.

The public outcome is unchanged (``unavailable`` / ``credential_unavailable``); a request-joined
companion diagnostic names the structural cause, known before any login is consulted.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

import finishup.observability.diagnostics as diagnostics_module
import finishup.service.ready_composition as ready_composition_module
from builders.ledger_adapters import FixedClock
from finishup.application.check import FinalSemanticEvaluation
from finishup.application.egress import PrivacyCoordinator
from finishup.domain.privacy import ProviderBinding
from finishup.ports.ledger import FrozenCase
from finishup.ports.start_catalog import StartCatalogPort
from finishup.protocol.models import SemanticReason, SemanticStatus
from integration.service.test_semantic_non_dispatch import (
    _INSTALLATION,  # pyright: ignore[reportPrivateUsage]
    _REQUEST,  # pyright: ignore[reportPrivateUsage]
    _Catalog,  # pyright: ignore[reportPrivateUsage]
    _frozen,  # pyright: ignore[reportPrivateUsage]
    _Privacy,  # pyright: ignore[reportPrivateUsage]
    _records,  # pyright: ignore[reportPrivateUsage]
    _route,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

type _Evaluate = Callable[[FrozenCase, tuple[object, ...]], object]


def _evaluator(state: Callable[[], str | None] | None) -> _Evaluate:
    async def resolve_provider() -> ProviderBinding | None:
        return None

    factory = cast(
        "Callable[..., _Evaluate]",
        getattr(ready_composition_module, "_privacy_gated_semantic_evaluator"),
    )
    return factory(
        cast(PrivacyCoordinator, _Privacy()),
        FixedClock(),
        _INSTALLATION,
        resolve_provider,
        cast(StartCatalogPort, _Catalog(_route())),
        ready_composition_module.IdPort(),
        external_runtime_state=state,
    )


async def test_a_stranded_runtime_names_its_structural_cause_beside_the_public_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)

    result = cast(
        FinalSemanticEvaluation,
        await _evaluator(lambda: "codex_runtime_executable_changed")(_frozen(), ()),  # pyright: ignore[reportGeneralTypeIssues]
    )

    assert (result.status, result.reason) == (
        SemanticStatus.UNAVAILABLE,
        SemanticReason.CREDENTIAL_UNAVAILABLE,
    )
    records = _records(tmp_path)
    assert [(record["operation"], record["reason"]) for record in records] == [
        ("semantic_external_runtime_unready", "codex_runtime_executable_changed"),
        ("semantic_not_dispatched_credential_unavailable", "credential_unavailable"),
    ]
    assert {record["request_id"] for record in records} == {_REQUEST}
    assert str(tmp_path) not in diagnostics_module.diagnostic_log_path(root=tmp_path).read_text(
        encoding="ascii"
    )


@pytest.mark.parametrize("state", [None, lambda: None, lambda: "ready"])
async def test_no_companion_record_without_a_structural_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: Callable[[], str | None] | None,
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)

    await _evaluator(state)(_frozen(), ())  # pyright: ignore[reportGeneralTypeIssues]

    assert [record["operation"] for record in _records(tmp_path)] == [
        "semantic_not_dispatched_credential_unavailable"
    ]


async def test_a_failing_structural_probe_never_changes_the_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(diagnostics_module, "log_dir", lambda: tmp_path)

    def broken() -> str | None:
        raise OSError("unreadable")

    result = cast(
        FinalSemanticEvaluation,
        await _evaluator(broken)(_frozen(), ()),  # pyright: ignore[reportGeneralTypeIssues]
    )

    assert result.reason is SemanticReason.CREDENTIAL_UNAVAILABLE
    assert [record["operation"] for record in _records(tmp_path)] == [
        "semantic_not_dispatched_credential_unavailable"
    ]
