"""#1118 R5: each read names the exchange that first carried its result, recorded when sent.

Through the real composition (only the provider is scripted): after a format repair the read's own
ordinal is no longer an exchange index, and the record still names the receipt of the exchange
that carried it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from finishup.protocol.models import SemanticStatus
from integration.service import test_reviewer_conversation_composition as c

pytestmark = pytest.mark.anyio


def _receipt(request_id: str) -> str:
    # The composition audit's receipt id for the exchange sent under ``request_id``.
    return "egr_" + request_id.removeprefix("req_")


async def test_a_read_names_the_exchange_that_first_carried_it_after_a_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[str] = []
    dispatch = c._ScriptedGateway.dispatch_external_semantic  # pyright: ignore[reportPrivateUsage]

    async def recording(self: Any, case: Any, authorization: Any, deadline: Any) -> object:
        sent.append(case.request_id)
        return await dispatch(self, case, authorization, deadline)

    monkeypatch.setattr(
        c._ScriptedGateway,  # pyright: ignore[reportPrivateUsage]
        "dispatch_external_semantic",
        recording,
    )
    result, gateway, _ = await c._run(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        {},  # repaired
        c._read_file("calc.py"),  # pyright: ignore[reportPrivateUsage]
        c._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    assert result.status is SemanticStatus.SUCCEEDED and len(sent) == 3
    assert result.reviewer is not None
    (read,) = result.reviewer.reads
    # The result first left in the third exchange, not the second (the read's own ordinal).
    assert '"call_index":1' in gateway.exchanges[2][1][-1][1]
    assert read.disclosure == _receipt(sent[2])
