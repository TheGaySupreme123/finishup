"""Metadata-only reads of requested output paths at check time (issue #977, ADR-033)."""

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path

import pytest

from yoetz.adapters.git_change_capture import GitChangeCaptureAdapter
from yoetz.application.check_change import requested_output_states
from yoetz.domain.events import (
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
)
from yoetz.domain.values import obligation_id
from yoetz.kernel.projections import ProjectionState
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    REQUESTED_OUTPUT_GIT_IGNORED_GAP,
    REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,
    REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,
    REQUESTED_OUTPUT_UNCHANGED_GAP,
    requested_output_facts,
)
from yoetz.ports.change_capture import CheckWorkspaceSource

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": os.fspath(repository),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
        },
    )
    return completed.stdout.decode("utf-8")


@pytest.fixture(autouse=True)
def isolated_global_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    (repository / ".gitignore").write_text("checkpoints/\n", encoding="utf-8")
    (repository / "kept.txt").write_text("kept\n", encoding="utf-8")
    (repository / "gone.txt").write_text("gone\n", encoding="utf-8")
    _git(repository, "add", "--", ".gitignore", "kept.txt", "gone.txt")
    _git(
        repository,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "baseline",
    )
    return repository


def test_probe_reports_existence_and_ignore_source(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (repository / "checkpoints").mkdir()
    (repository / "checkpoints" / "model.pt").write_bytes(b"\0")
    (repository / "output").mkdir()
    (repository / "output" / "flag.txt").write_text("flag\n", encoding="utf-8")
    exclude = repository / ".git" / "info" / "exclude"
    exclude.write_text(exclude.read_text(encoding="utf-8") + "/output/\n", encoding="utf-8")
    adapter = GitChangeCaptureAdapter()

    probes = adapter.probe_requested_paths(
        os.fspath(repository),
        (
            "kept.txt",
            os.fspath(repository / "checkpoints" / "model.pt"),
            "output/flag.txt",
            "missing/report.json",
            "/etc/hosts",
            "../escape.txt",
        ),
    )

    kept, checkpoint, flag, missing, outside, escape = probes
    assert (kept.location, kept.exists, kept.ignored) == ("inside", True, False)
    assert checkpoint.relative == "checkpoints/model.pt"
    assert (checkpoint.ignored, checkpoint.ignore_source, checkpoint.ignore_file) == (
        True,
        "repository_file",
        ".gitignore",
    )
    assert (flag.ignored, flag.ignore_source) == (True, "info_exclude")
    assert (missing.exists, missing.ignored) == (False, False)
    assert outside.location == "outside" and outside.relative is None
    assert escape.location == "outside"


def test_probe_never_follows_a_link(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "report.json").write_text("{}", encoding="utf-8")
    (repository / "linked").symlink_to(elsewhere, target_is_directory=True)

    (probe,) = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), ("linked/report.json",)
    )
    assert probe.exists is None


def _projection(*values: str, edited: tuple[str, ...] = ()) -> ProjectionState:
    from builders.observed_runs import ObservedLedger
    from yoetz.domain.events import ActionKind, ActionRecordedPayload, EventSchema
    from yoetz.domain.values import action_id

    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliver the outputs",
            evidence_expectation="The files",
            status=ObligationStatus.OPEN,
            requested_items=tuple(RequestedItem(RequestedItemKind.FILE, value) for value in values),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    if edited:
        ledger.append(
            EventSchema("action_recorded", "1.0.0"),
            ActionRecordedPayload(
                action_id("act_00000000-0000-4000-8000-000000000901"),
                ActionKind.EDIT,
                "Wrote the requested outputs.",
                attempted_items=tuple(sorted(edited)),
            ),
            observed=False,
        )
    return replay(ledger.prefix)


def test_check_time_states_feed_the_requested_output_facts(tmp_path: Path) -> None:
    """shadow-relay: the agent excluded /output/ from Git; atrx: the report was never written."""

    repository = _repository(tmp_path)
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    (repository / "output").mkdir()
    (repository / "output" / "flag.txt").write_text("flag\n", encoding="utf-8")
    exclude = repository / ".git" / "info" / "exclude"
    exclude.write_text(exclude.read_text(encoding="utf-8") + "/output/\n", encoding="utf-8")
    (repository / "checkpoints").mkdir()
    (repository / "checkpoints" / "model.pt").write_bytes(b"\0")
    (repository / "gone.txt").unlink()
    capture = adapter.capture_metadata(os.fspath(repository), base)
    projection = _projection(
        "output/flag.txt",
        "mutation.report.json",
        "checkpoints/model.pt",
        "kept.txt",
        "gone.txt",
        "/elsewhere/out.json",
        edited=("/elsewhere/out.json", "kept.txt"),
    )
    source = CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64)

    states = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=capture,
            source=source,
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000001",
        )
    )
    absent, markers = requested_output_facts(projection, states, blocked=())

    assert absent == ((_OBLIGATION, 1),)  # mutation.report.json; gone.txt is a tracked deletion
    assert {code for code, _ in markers} == {
        REQUESTED_OUTPUT_GIT_IGNORED_GAP,  # output/ excluded through .git/info/exclude
        REQUESTED_OUTPUT_IGNORED_BY_REPOSITORY_GAP,  # checkpoints/ ignored by the base .gitignore
        REQUESTED_OUTPUT_UNCHANGED_GAP,  # kept.txt, recorded as edited
        REQUESTED_OUTPUT_OUTSIDE_WORKSPACE_GAP,  # /elsewhere/out.json, recorded as edited
    }

    # tb4v1: the same unchanged tracked file and outside path, only read as inputs, are no
    # requested-output facts; the new untracked report is counted as changed.
    (repository / "mutation.report.json").write_text("{}\n", encoding="utf-8")
    capture = adapter.capture_metadata(os.fspath(repository), base)
    inputs = _projection("kept.txt", "/elsewhere/out.json", "mutation.report.json")
    states = asyncio.run(
        requested_output_states(
            projection=inputs,
            capture=capture,
            source=source,
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000002",
        )
    )
    assert states[(_OBLIGATION, 2)].changed is True
    assert requested_output_facts(inputs, states, blocked=()) == ((), ())


def test_without_a_capture_every_requested_file_is_unverified() -> None:
    projection = _projection("out.json")
    states = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=None,
            source=None,
            port=None,
            request_id="req_00000000-0000-4000-8000-000000000001",
        )
    )
    assert {state.location for state in states.values()} == {"unverified"}


def test_a_requested_directory_is_changed_by_new_files_under_it(tmp_path: Path) -> None:
    """tb4n1 E1/E7: retro-console-soc (/app/src), risk-scorer (/app/parityctl), nextjs (/app).

    The agents named their output directory, and the workspace root itself, in edit actions and
    wrote new files under it. The capture lists files only, so an exact path match reported each
    directory unchanged and the root outside the workspace.
    """

    repository = _repository(tmp_path)
    for relative in ("parityctl/cli.py", "untouched/a.txt", "sr/keep.txt"):
        (repository / relative).parent.mkdir(exist_ok=True)
        (repository / relative).write_text("old\n", encoding="utf-8")
    _git(repository, "add", "--", "parityctl/cli.py", "untouched/a.txt", "sr/keep.txt")
    _git(
        repository,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "inputs",
    )
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    root = os.fspath(repository)
    values = (
        root + "/src",  # new untracked files only
        root + "/parityctl/",  # a tracked file modified; trailing slash
        root,  # the workspace root
        root + "/untouched",  # nothing under it changed
        root + "/sr",  # a sibling prefix of src/ is not src/
    )
    projection = _projection(*values, edited=values)
    source = CheckWorkspaceSource(root, "hmac-sha256:" + "0" * 64)

    before = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=adapter.capture_metadata(root, base),
            source=source,
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000003",
        )
    )
    assert before[(_OBLIGATION, 2)].location == "inside"
    assert before[(_OBLIGATION, 2)].changed is False

    (repository / "src").mkdir()
    for name in ("apu2a03.sv", "console_system.sv", "cpu6502.sv", "ppu2c02.sv"):
        (repository / "src" / name).write_text("module m; endmodule\n", encoding="utf-8")
    (repository / "parityctl" / "cli.py").write_text("new\n", encoding="utf-8")
    capture = adapter.capture_metadata(root, base)
    states = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=capture,
            source=source,
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000004",
        )
    )

    assert [states[(_OBLIGATION, index)].changed for index in range(5)] == [
        True,
        True,
        True,
        False,
        False,
    ]
    _, markers = requested_output_facts(projection, states, blocked=())
    # Only the genuinely untouched directories stay unchanged; nothing is "outside".
    assert {code for code, _ in markers} == {REQUESTED_OUTPUT_UNCHANGED_GAP}


def test_the_workspace_root_probe_is_inside_and_existing(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    (probe,) = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository), (os.fspath(repository),)
    )
    assert (probe.location, probe.relative, probe.exists, probe.ignored) == (
        "inside",
        ".",
        True,
        False,
    )


def test_probe_reports_whether_a_directory_holds_a_file(tmp_path: Path) -> None:
    """#1002: an existing directory with no file beneath it delivers nothing."""

    repository = _repository(tmp_path)
    (repository / "empty").mkdir()
    (repository / "hollow" / "a" / "b").mkdir(parents=True)
    (repository / "deep" / "a" / "b").mkdir(parents=True)
    (repository / "deep" / "a" / "b" / "out.sv").write_text("module m; endmodule\n")
    (repository / "linked_only").mkdir()
    (repository / "linked_only" / "link").symlink_to(tmp_path)

    probes = GitChangeCaptureAdapter().probe_requested_paths(
        os.fspath(repository),
        ("empty", "hollow", "deep", "linked_only", "kept.txt", "missing", "."),
    )

    assert [probe.holds_file for probe in probes] == [False, False, True, True, None, None, True]
    assert all(probe.exists is True for probe in probes[:5])


def _items_projection(*items: RequestedItem, edited: tuple[str, ...] = ()) -> ProjectionState:
    from builders.observed_runs import ObservedLedger
    from yoetz.domain.events import ActionKind, ActionRecordedPayload, EventSchema
    from yoetz.domain.values import action_id

    ledger = ObservedLedger()
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=_OBLIGATION,
            description="Deliver the outputs",
            evidence_expectation="The files",
            status=ObligationStatus.OPEN,
            requested_items=items,
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    if edited:
        ledger.append(
            EventSchema("action_recorded", "1.0.0"),
            ActionRecordedPayload(
                action_id("act_00000000-0000-4000-8000-000000000902"),
                ActionKind.EDIT,
                "Wrote the requested outputs.",
                attempted_items=tuple(sorted(edited)),
            ),
            observed=False,
        )
    return replay(ledger.prefix)


def test_roles_and_directories_at_check_time(tmp_path: Path) -> None:
    """tb4n1 layout-config and retro-console-soc, with the roles declared (#1002).

    The read-only /app/layout_spec.json input is never a requested-output fact, even when an edit
    action names it; /app/src as an output directory is absent while missing or holding only
    empty directories, and changed once files land under it. A declared output file the change
    leaves untouched is reported without any edit action naming it.
    """

    from yoetz.domain.events import RequestedItemRole

    repository = _repository(tmp_path)
    (repository / "layout_spec.json").write_text("{}\n", encoding="utf-8")
    _git(repository, "add", "--", "layout_spec.json")
    _git(
        repository,
        "-c",
        "user.name=Yoetz Test",
        "-c",
        "user.email=yoetz@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "spec",
    )
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    root = os.fspath(repository)
    items = (
        RequestedItem(RequestedItemKind.FILE, root + "/layout_spec.json", RequestedItemRole.INPUT),
        RequestedItem(RequestedItemKind.DIRECTORY, root + "/src", RequestedItemRole.OUTPUT),
        RequestedItem(RequestedItemKind.FILE, "kept.txt", RequestedItemRole.OUTPUT),
        RequestedItem(RequestedItemKind.FILE, root + "/missing_input.csv", RequestedItemRole.INPUT),
        # No role: a directory named as a plain file item keeps the 1.0.0 reading.
        RequestedItem(RequestedItemKind.FILE, root + "/hollow"),
    )
    projection = _items_projection(*items, edited=(items[0].value,))
    source = CheckWorkspaceSource(root, "hmac-sha256:" + "0" * 64)

    def facts() -> tuple[object, ...]:
        states = asyncio.run(
            requested_output_states(
                projection=projection,
                capture=adapter.capture_metadata(root, base),
                source=source,
                port=adapter,
                request_id="req_00000000-0000-4000-8000-000000000005",
            )
        )
        # Inputs are not read at all.
        assert (_OBLIGATION, 0) not in states and (_OBLIGATION, 3) not in states
        return requested_output_facts(projection, states, blocked=())

    (repository / "hollow" / "sub").mkdir(parents=True)
    unchanged = ((REQUESTED_OUTPUT_UNCHANGED_GAP, _OBLIGATION),)
    assert facts() == (((_OBLIGATION, 1),), unchanged)  # src missing; kept.txt untouched

    (repository / "src" / "rtl").mkdir(parents=True)
    assert facts() == (((_OBLIGATION, 1),), unchanged)  # only empty directories

    for name in ("apu2a03.sv", "cpu6502.sv"):
        (repository / "src" / "rtl" / name).write_text("module m; endmodule\n", encoding="utf-8")
    (repository / "kept.txt").write_text("rewritten\n", encoding="utf-8")
    assert facts() == ((), ())
