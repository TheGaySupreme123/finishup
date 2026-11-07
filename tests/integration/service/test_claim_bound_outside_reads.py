"""A claim-bound task reads outside its workspace only where the client's owner admitted it.

ADR-051 decision 5 and #1220, in ``listed`` mode. The server names a declared test outside the
claimed workspace; the client's workspace agent (the product's own handler, behind the test
agent) reads it only beneath a folder the owner admitted for that server on the client
(``finishup server folders add``). Not admitted, the server never pins the test and the reviewer
is never offered it, though the very same file is there and readable, and the check discloses
``outside_reads_not_listed`` with the owner's two ways out; admitted, it is pinned and offered as
a local service offers it. A task input the task names beneath a root the server's own policy
admits is left unread by the agent until the owner admits it on the client: only that input is
missing, the rest of the check-time change stands, and the capture records the same disclosure,
never a silent absence.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

import finishup.service.ready_composition as ready_composition_module
from builders.workspace_agent_fake import FakeWorkspaceAgent
from finishup.adapters.task_input_read import read_declared_test
from finishup.domain.receipts import OUTSIDE_READS_NOT_LISTED_GAP
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
    if not admitted:
        # A second test in the same unlisted folder: the case object counts both.
        second = test.with_name("test_second_rule.py")
        second.write_text(_TEST_TEXT)
        second.chmod(0o600)
        candidates += (DeclaredTestCandidate(os.fspath(second), "res_criterion"),)

    def declared(_projection: object, _statement: str | None) -> tuple[DeclaredTestCandidate, ...]:
        return candidates

    monkeypatch.setattr(ready_composition_module, "declared_test_candidates", declared)
    # What the job's case object froze, as recovery reads it back.
    frozen: list[tuple[object, ...]] = []
    publish = getattr(ready_composition_module, "_publish_semantic_case_object")
    read_case = getattr(ready_composition_module, "_read_semantic_case")

    async def spy(runtime: object, **kwargs: object) -> object:
        ref = await publish(runtime, **kwargs)
        frozen.append(await read_case(runtime, ref))
        return ref

    monkeypatch.setattr(ready_composition_module, "_publish_semantic_case_object", spy)
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
    # Not offered because the owner did not list it: the check says so, never in silence, and the
    # job's case object freezes it, so a recovered job builds the same case.
    assert (OUTSIDE_READS_NOT_LISTED_GAP in result.case_content_gaps) is not admitted
    ((stored),) = frozen
    assert stored[6] == (0 if admitted else 2)


@pytest.mark.parametrize("admitted", [False, True], ids=["not-admitted", "admitted"])
async def test_a_task_input_the_owner_did_not_list_costs_only_that_input(
    tmp_path: Path, admitted: bool
) -> None:
    from finishup.application.check_change import (
        _with_outside_inputs,  # pyright: ignore[reportPrivateUsage]
    )
    from finishup.ports.change_capture import CheckChangeCapture
    from finishup.service.workspace_routing import WorkspaceRouting

    specs = (tmp_path / "specs").resolve()
    notes = (tmp_path / "notes").resolve()
    for folder, name, text in ((specs, "spec.md", "SPEC_MARKER\n"), (notes, "n.md", "NOTE\n")):
        folder.mkdir(mode=0o700)
        (folder / name).write_text(text)
        (folder / name).chmod(0o600)
    hub = WorkspaceAgentHub(inline_wait_seconds=0.5, background_wait_seconds=0.5)
    agent = FakeWorkspaceAgent(claim_bound._reviewed_repository(tmp_path))  # pyright: ignore[reportPrivateUsage]
    agent.admitted_folders.append(os.fspath(notes))
    if admitted:
        agent.admitted_folders.append(os.fspath(specs))
    await claim_bound._attach(hub, agent)  # pyright: ignore[reportPrivateUsage]
    assert agent.handle is not None
    routing = WorkspaceRouting.compose(hub, claim_bound.SpyLocalCapture())
    # The server's own policy admits both roots; the check-time reader the service composes.
    reader = getattr(ready_composition_module, "_outside_input_reader")(
        (os.fspath(notes), os.fspath(specs)), (), routing
    )
    values = (f"{specs}/spec.md", f"{notes}/n.md", f"{specs}/missing.md")
    change = CheckChangeCapture(
        base="task_start",
        text=b"diff --git a/calc.py b/calc.py\n",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
    )
    capture = await asyncio.to_thread(
        _with_outside_inputs,
        change,
        values,
        reader,
        agent.handle,
        verification_paths=frozenset(),
    )
    assert "read_outside_inputs" in agent.operations
    # The change itself stands either way: listed mode costs only the input it did not list.
    assert capture.text == change.text
    read = [(item.path, item.root) for item in capture.inputs]
    if admitted:
        assert read == [(values[0], os.fspath(specs)), (values[1], os.fspath(notes))]
        assert capture.outside_inputs_not_listed == 0
        return
    assert read == [(values[1], os.fspath(notes))]
    # Recorded as a count, never which file: the receipt's fixed line comes from it. The missing
    # file is not counted as left out, as a local read finds nothing there either.
    assert capture.outside_inputs_not_listed == 1


async def test_a_kept_copys_current_read_names_a_folder_the_owner_no_longer_lists(
    tmp_path: Path,
) -> None:
    """The check compares each kept copy with the file now (#1118 unit 1). A claim-bound task's
    agent names the kept paths whose folder the owner no longer lists, so their copies are not
    sent, as a copy whose root the owner no longer admits is not (ADR-051 decision 5)."""

    from finishup.application.check_change import CurrentInputsRead
    from finishup.service.workspace_routing import WorkspaceRouting

    specs = (tmp_path / "specs").resolve()
    notes = (tmp_path / "notes").resolve()
    for folder, name, text in ((specs, "spec.md", "SPEC_MARKER\n"), (notes, "n.md", "NOTE\n")):
        folder.mkdir(mode=0o700)
        (folder / name).write_text(text)
        (folder / name).chmod(0o600)
    hub = WorkspaceAgentHub(inline_wait_seconds=0.5, background_wait_seconds=0.5)
    agent = FakeWorkspaceAgent(claim_bound._reviewed_repository(tmp_path))  # pyright: ignore[reportPrivateUsage]
    agent.admitted_folders.append(os.fspath(notes))
    await claim_bound._attach(hub, agent)  # pyright: ignore[reportPrivateUsage]
    assert agent.handle is not None
    routing = WorkspaceRouting.compose(hub, claim_bound.SpyLocalCapture())
    current = getattr(ready_composition_module, "_current_input_reader")(
        (os.fspath(notes), os.fspath(specs)), (agent.handle,), routing
    )
    paths = (f"{specs}/spec.md", f"{notes}/n.md")
    found = await asyncio.to_thread(current, paths)
    assert found == CurrentInputsRead({paths[1]: b"NOTE\n"}, frozenset({paths[0]}))
    assert "snapshot_outside_inputs" in agent.operations
