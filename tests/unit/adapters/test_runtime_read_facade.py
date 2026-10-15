"""Read-route runtime facades must cover what read-routed code calls.

``status(view=operation)`` failed for every caller, every time: it calls ``lookup_task_operation``, but
a read route hands the application ``_ReadLedger``, a ``__slots__`` facade that exposed only a
subset of the port and not that one, so the call raised ``AttributeError`` before reaching data — and
the recovery view was unavailable exactly when a caller needed it.

Every status test passed throughout, because they drive the raw ledger directly and never cross
the routing facade. Two surfaces that have to agree, and nothing compared them. This does.
"""

from __future__ import annotations

import ast
import pathlib
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import cast

import pytest

from finishup.adapters import runtime as runtime_module
from finishup.application import status as status_module
from finishup.ports.ledger import LedgerPort

# ``execute_status`` is the read-routed entry point: it routes with ``RouteAccess.PAYLOAD_READ``
# and therefore receives the facades below rather than the real ports. Write and import-review
# routes get the real objects, so their mutator calls are legitimately absent from the facades.
assert status_module.__file__ is not None
_READ_ROUTED_MODULE = pathlib.Path(status_module.__file__)

_FACADES = {
    "ledger": runtime_module._ReadLedger,  # pyright: ignore[reportPrivateUsage]
    "objects": runtime_module._PayloadObjects,  # pyright: ignore[reportPrivateUsage]
    "importer": runtime_module._StatusImporter,  # pyright: ignore[reportPrivateUsage]
}


def _calls_on_runtime_attributes(source: pathlib.Path) -> dict[str, set[str]]:
    """Collect direct ``runtime.<port>.<method>(...)`` calls, not local port aliases."""

    found: dict[str, set[str]] = {name: set() for name in _FACADES}
    tree = ast.parse(source.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        owner = func.value
        if (
            isinstance(owner, ast.Attribute)
            and owner.attr in found
            and isinstance(owner.value, ast.Name)
            and owner.value.id == "runtime"
        ):
            found[owner.attr].add(func.attr)
    return found


def test_read_facades_expose_every_port_method_the_read_view_calls() -> None:
    """Anything ``execute_status`` calls on a routed port must exist on that port's facade."""

    called = _calls_on_runtime_attributes(_READ_ROUTED_MODULE)
    assert called["ledger"], "no runtime.ledger calls found; the scan is broken, not the facade"

    missing: dict[str, list[str]] = {}
    for attribute, facade in _FACADES.items():
        exposed = {name for name in dir(facade) if not name.startswith("_")}
        absent = sorted(called[attribute] - exposed)
        if absent:
            missing[attribute] = absent
    assert not missing, (
        f"read-routed status calls methods the facade does not expose: {missing}. "
        "A read route receives the facade, so this raises AttributeError in production while "
        "tests that use the raw port keep passing. The scan detects direct runtime.<port> calls "
        "only; extend it before relying on aliases such as `ledger = runtime.ledger`."
    )


def test_read_ledger_can_look_up_an_operation() -> None:
    """Pin the specific method whose absence broke recovery, so it cannot silently vanish."""

    facade = runtime_module._ReadLedger  # pyright: ignore[reportPrivateUsage]
    assert callable(getattr(facade, "lookup_operation", None))
    assert callable(getattr(facade, "lookup_task_operation", None))
    assert callable(getattr(facade, "load_disclosure_wait", None))
    # Closure readiness (#913) must see a check that holds the frontier through the read route.
    assert callable(getattr(facade, "has_active_frozen_case", None))


@dataclass(frozen=True)
class _Record:
    event_id: str
    payload: object | None


class _Ledger:
    def __init__(self, records: tuple[_Record, ...]) -> None:
        self.records = records
        self.calls: list[tuple[str, int, int | None]] = []

    async def _events(self) -> AsyncIterator[_Record]:
        for record in self.records:
            yield record

    def load_events(
        self, session_id: str, *, after: int = 0, through: int | None = None
    ) -> AsyncIterator[_Record]:
        self.calls.append((session_id, after, through))
        return self._events()

    async def load_frontier(self) -> str:
        return "frontier"


def test_structural_ledger_exposes_no_payload_derived_read() -> None:
    """A keyless lease reads envelopes and the frontier; projections derive from payloads (#839)."""

    facade = runtime_module._StructuralLedger  # pyright: ignore[reportPrivateUsage]
    assert {name for name in dir(facade) if not name.startswith("_")} == {
        "load_events",
        "load_frontier",
    }


@pytest.mark.anyio
async def test_structural_ledger_strips_payloads_a_warm_entry_decoded() -> None:
    """A warm entry holds decoded payloads; a structural lease on it must not see them (#839)."""

    records = (
        _Record("evt_payload", {"requested_items": ["src/secret.py"]}),
        _Record("evt_gap", None),
    )
    ledger = _Ledger(records)
    facade = runtime_module._StructuralLedger(  # pyright: ignore[reportPrivateUsage]
        cast(LedgerPort, ledger)
    )
    seen = [record async for record in facade.load_events("ses_1", after=2, through=9)]
    assert ledger.calls == [("ses_1", 2, 9)]
    assert [(record.event_id, record.payload) for record in seen] == [
        ("evt_payload", None),
        ("evt_gap", None),
    ]
    # A record that already carries no payload passes through unchanged.
    assert seen[1] is records[1]
    assert await facade.load_frontier() == "frontier"
