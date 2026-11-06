"""A claim-bound task reads outside its workspace only where the client's owner admitted it.

ADR-051 decision 5 and #1220. The server names a declared test outside the claimed workspace;
the client's workspace agent (the product's own handler, behind the test agent) reads it only
beneath a folder the owner admitted for that server on the client (``finishup server folders
add``). Not admitted, the server never pins the test and the reviewer is never offered it, though
the very same file is there and readable; admitted, it is pinned and offered as a local service
offers it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import finishup.service.ready_composition as ready_composition_module
from builders.workspace_agent_fake import FakeWorkspaceAgent
from finishup.adapters.task_input_read import read_declared_test
from finishup.kernel.declared_checks import DeclaredTestCandidate
from finishup.service.workspace_hub import WorkspaceAgentHub
from integration.service import test_claim_bound_sessions as claim_bound
from integration.service.test_ready_composition import (  # noqa: F401 - autouse SQLite policy
    _sqlite_policy,  # pyright: ignore[reportPrivateUsage, reportUnusedImport]
)

pytestmark = pytest.mark.anyio

_TEST_TEXT = "def test_stop_rule():\n    assert True\n"


def _outside_test(tmp_path: Path) -> Path:
    folder = (tmp_path / "scratch").resolve()
    folder.mkdir(mode=0o700)
    test = folder / "test_stop_rule.py"
    test.write_text(_TEST_TEXT)
    test.chmod(0o600)
    return test


@pytest.mark.parametrize("admitted", [False, True], ids=["not-admitted", "admitted"])
async def test_an_outside_declared_test_is_pinned_only_beneath_an_admitted_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, admitted: bool
) -> None:
    import builders.privacy_policies as policies
    from integration.service import test_reviewer_conversation_composition as reviewer

    # A review channel roomy enough to offer declared tests (the reviewer suite's own policy).
    roomy = reviewer._ROOMY  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(policies, "minimal_external_policy", lambda: roomy)
    test = _outside_test(tmp_path)
    # The file is readable here, exactly as a local service would read it.
    assert read_declared_test(os.fspath(test), excluded=()) == _TEST_TEXT.encode()
    candidates = (DeclaredTestCandidate(os.fspath(test), "res_criterion"),)

    def declared(_projection: object, _statement: str | None) -> tuple[DeclaredTestCandidate, ...]:
        return candidates

    monkeypatch.setattr(ready_composition_module, "declared_test_candidates", declared)
    hub = WorkspaceAgentHub(inline_wait_seconds=0.5, background_wait_seconds=0.5)
    agent = FakeWorkspaceAgent(claim_bound._reviewed_repository(tmp_path))  # pyright: ignore[reportPrivateUsage]
    if admitted:
        agent.admitted_folders.append(os.fspath(test.parent))
    await claim_bound._attach(hub, agent)  # pyright: ignore[reportPrivateUsage]
    result, gateway = await claim_bound._review(  # pyright: ignore[reportPrivateUsage]
        tmp_path,
        monkeypatch,
        hub,
        reviewer._FINAL,  # pyright: ignore[reportPrivateUsage]
    )
    assert result.status.value == "succeeded", (result.status, result.reason)
    # The server asked the agent for it either way; only the client's record decides.
    assert "read_declared_test" in agent.operations, agent.operations
    first = gateway.exchanges[0][1]
    packet = json.loads(first[1][1])
    listed = packet["review_packet"].get("declared_tests", [])
    catalog = json.loads(first[2][1])["reviewer_catalog"]["read_file_roots"]
    declared_roots = [root for root in catalog if root.get("standing") == "declared_test"]
    if admitted:
        assert [(row["ref"], row["path"]) for row in listed] == [("dt1", os.fspath(test))]
        assert declared_roots and declared_roots[0]["covers"] == ["dt1"]
    else:
        assert listed == []
        assert declared_roots == []
        assert os.fspath(test) not in first[1][1]
