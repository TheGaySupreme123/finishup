"""tb4n1 regressions for the declared delivered set against a real Git change (#1005, ADR-035)."""

from __future__ import annotations

import asyncio
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.adapters.git_change_capture import GitChangeCaptureAdapter
from finishup.application.check_change import requested_output_states
from finishup.domain.events import (
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
)
from finishup.domain.values import event_id, obligation_id
from finishup.kernel.delivered_set import (
    DeliverableAssessment,
    DeliverableSnapshot,
    assess_deliverables,
    content_moved_declared_items,
    declared_output_removed,
)
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key
from finishup.ports.change_capture import CheckWorkspaceSource

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": os.defpath,
}


@pytest.fixture(autouse=True)
def declared_outputs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Treat role-less 1.0.0 items as ``output``; L6's 1.1.0 role is not on this branch."""

    from finishup.kernel import delivered_set

    def output_role(item: object) -> object:
        del item
        return "output"

    monkeypatch.setattr(delivered_set, "item_role", output_role)


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


@pytest.fixture(autouse=True)
def isolated_global_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ("git", *arguments),
        cwd=repository,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        env={**_GIT_ENV, "HOME": os.fspath(repository)},
    )


def _repository(tmp_path: Path, files: dict[str, str]) -> Path:
    repository = tmp_path / "app"
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet")
    for name, text in files.items():
        (repository / name).write_text(text, encoding="utf-8")
    _git(repository, "add", "--", *files)
    _git(
        repository,
        "-c",
        "user.name=FinishUP Test",
        "-c",
        "user.email=finishup@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "baseline",
    )
    return repository


def _projection(*values: str) -> ProjectionState:
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
    return replay(ledger.prefix)


def _states(repository: Path, base: object, projection: ProjectionState) -> dict[object, object]:
    adapter = GitChangeCaptureAdapter()
    capture = adapter.capture_metadata(os.fspath(repository), base)  # type: ignore[arg-type]
    return asyncio.run(  # type: ignore[return-value]
        requested_output_states(
            projection=projection,
            capture=capture,
            source=CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64),
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000001",
        )
    )


def _moved(repository: Path, base: object, *values: str) -> tuple[object, ...]:
    projection = _projection(*values)
    states = _states(repository, base, projection)
    return content_moved_declared_items(projection, states)  # type: ignore[arg-type]


def _removed(repository: Path, base: object, *values: str) -> tuple[object, ...]:
    adapter = GitChangeCaptureAdapter()
    capture = adapter.capture_metadata(os.fspath(repository), base)  # type: ignore[arg-type]
    projection = _projection(*values)
    states = asyncio.run(
        requested_output_states(
            projection=projection,
            capture=capture,
            source=CheckWorkspaceSource(os.fspath(repository), "hmac-sha256:" + "0" * 64),
            port=adapter,
            request_id="req_00000000-0000-4000-8000-000000000001",
        )
    )
    return declared_output_removed(projection, states)


def test_music_harmony_declared_file_moved_out_of_the_workspace(tmp_path: Path) -> None:
    """tb4n1 music-harmony: the delivered score was moved to /tmp "to reduce the review input"."""

    repository = _repository(tmp_path, {"harmony.musicxml": "<score/>\n", "notes.txt": "n\n"})
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    elsewhere = tmp_path / "tmp"
    elsewhere.mkdir()
    (repository / "harmony.musicxml").rename(elsewhere / "harmony.musicxml")

    declared = os.fspath(repository / "harmony.musicxml")
    assert _removed(repository, base, declared, "notes.txt") == (_OBLIGATION,)
    # An undeclared deletion is not the declared set's business.
    assert _removed(repository, base, "notes.txt") == ()


def test_declared_file_renamed_inside_the_workspace(tmp_path: Path) -> None:
    repository = _repository(tmp_path, {"harmony.musicxml": "<score>\n" * 20})
    adapter = GitChangeCaptureAdapter()
    base = adapter.read_task_base(os.fspath(repository))
    _git(repository, "mv", "--", "harmony.musicxml", "review-copy.musicxml")

    assert _removed(repository, base, "harmony.musicxml") == (_OBLIGATION,)
    # Restoring the delivered file clears the fact.
    (repository / "review-copy.musicxml").rename(repository / "harmony.musicxml")
    _git(repository, "add", "--", "harmony.musicxml")
    assert _removed(repository, base, "harmony.musicxml") == ()


_TABLE = "".join(f"FREQ[{index}] = {index / 1000:.3f}\n" for index in range(200))


def _cracker(tmp_path: Path) -> tuple[Path, object]:
    repository = _repository(
        tmp_path,
        {"cracker.py": _TABLE + "def crack(): ...\n", "README.md": "Cracker\n"},
    )
    return repository, GitChangeCaptureAdapter().read_task_base(os.fspath(repository))


@pytest.mark.parametrize("model", ["english_model.bin", "english_model.py"])
def test_interleaved_vigenere_content_moved_is_disclosed(tmp_path: Path, model: str) -> None:
    """tb4n1 interleaved-vigenere: the table left cracker.py for an undelivered model file.

    The declared file still exists, so ``declared_output_removed`` stays silent; the line-count
    read shows it lost almost all of its base lines while an undeclared new file gained them.
    """

    repository, base = _cracker(tmp_path)
    (repository / "cracker.py").write_text(
        f"FREQ = load('{model}')\ndef crack(): ...\n", encoding="utf-8"
    )
    (repository / model).write_text(_TABLE, encoding="utf-8")
    declared = os.fspath(repository / "cracker.py")

    assert _removed(repository, base, declared) == ()
    assert _moved(repository, base, declared) == ((_OBLIGATION, 0),)
    # Moving the content back clears the disclosure.
    (repository / "cracker.py").write_text(_TABLE + "def crack(): ...\n", encoding="utf-8")
    assert _moved(repository, base, declared) == ()


def test_content_moved_into_a_modified_tracked_undeclared_file(tmp_path: Path) -> None:
    repository, base = _cracker(tmp_path)
    (repository / "cracker.py").write_text("def crack(): ...\n", encoding="utf-8")
    (repository / "README.md").write_text("Cracker\n" + _TABLE, encoding="utf-8")

    assert _moved(repository, base, "cracker.py") == ((_OBLIGATION, 0),)


def test_refactor_into_another_declared_output_is_not_disclosed(tmp_path: Path) -> None:
    repository, base = _cracker(tmp_path)
    (repository / "cracker.py").write_text(
        "from english_model import FREQ\ndef crack(): ...\n", encoding="utf-8"
    )
    (repository / "english_model.py").write_text(_TABLE, encoding="utf-8")

    assert _moved(repository, base, "cracker.py", "english_model.py") == ()
    # The same change with the new module undeclared is the disclosed shape.
    assert _moved(repository, base, "cracker.py") == ((_OBLIGATION, 0),)


def test_large_deletion_with_no_growth_elsewhere_is_not_disclosed(tmp_path: Path) -> None:
    repository, base = _cracker(tmp_path)
    (repository / "cracker.py").write_text("def crack(): ...\n", encoding="utf-8")
    # A small unrelated note is far less than half of what the declared file lost.
    (repository / "NOTES.md").write_text("trimmed the table\n", encoding="utf-8")

    assert _moved(repository, base, "cracker.py") == ()


def test_small_or_partial_shrink_is_not_disclosed(tmp_path: Path) -> None:
    repository = _repository(tmp_path, {"small.py": "x = 1\n" * 30, "big.py": "y = 2\n" * 200})
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    # Lost 15 lines (half of 30, but under the 20-line floor).
    (repository / "small.py").write_text("x = 1\n" * 15, encoding="utf-8")
    # Lost 80 of 200 lines (under half).
    (repository / "big.py").write_text("y = 2\n" * 120, encoding="utf-8")
    (repository / "moved.py").write_text("z = 3\n" * 200, encoding="utf-8")

    assert _moved(repository, base, "small.py", "big.py") == ()


def test_role_less_items_never_disclose_content_moved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.kernel import delivered_set

    def no_role(item: object) -> object:
        del item
        return None

    monkeypatch.setattr(delivered_set, "item_role", no_role)
    repository, base = _cracker(tmp_path)
    (repository / "cracker.py").write_text("def crack(): ...\n", encoding="utf-8")
    (repository / "english_model.bin").write_text(_TABLE, encoding="utf-8")

    projection = _projection("cracker.py")
    states = _states(repository, base, projection)
    assert content_moved_declared_items(projection, states) == ()  # type: ignore[arg-type]
    # The line-count read is not even made for a role-less item.
    assert all(getattr(state, "lines_lost", None) is None for state in states.values())


def test_line_count_read_skips_cr_lf_paths_and_stops_at_its_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Final review: a CR/LF path is skipped, not fatal; a spent budget stops further reads."""

    import finishup.adapters.git_change_capture as capture_module

    repository, base = _cracker(tmp_path)
    (repository / "odd\nname.txt").write_text("a\nb\n", encoding="utf-8")
    (repository / "first.txt").write_text("x\n" * 10, encoding="utf-8")
    (repository / "second.txt").write_text("y\n" * 10, encoding="utf-8")
    adapter = GitChangeCaptureAdapter()
    commit = cast(str, getattr(base, "commit"))
    counts = adapter.count_change_lines(os.fspath(repository), commit, ())
    paths = {item.path for item in counts.changed}
    assert "first.txt" in paths and "second.txt" in paths
    assert not any("\n" in path for path in paths)

    monkeypatch.setattr(capture_module, "_MAX_LINE_COUNT_TOTAL_BYTES", 20)
    bounded = adapter.count_change_lines(os.fspath(repository), commit, ())
    assert bounded.truncated
    assert len([item for item in bounded.changed if item.untracked]) < 2


def _resolved(*values: str) -> ProjectionState:
    from finishup.domain.values import evidence_id

    ledger = ObservedLedger()
    items = tuple(RequestedItem(RequestedItemKind.FILE, value) for value in values)
    for status, refs in (
        (ObligationStatus.OPEN, ()),
        (
            ObligationStatus.RESOLVED,
            (evidence_id("evd_00000000-0000-4000-8000-000000000009"),),
        ),
    ):
        ledger.append(
            EventSchema("obligation_published", "1.0.0"),
            ObligationPublishedPayload(
                obligation_id=_OBLIGATION,
                description="Deliver the outputs",
                evidence_expectation="The files",
                status=status,
                requested_items=items,
                resolution_evidence_refs=refs,
            ),
            observed=False,
        )
        if status is ObligationStatus.OPEN:
            ledger.append(
                EventSchema("plan_published", "1.0.0"),
                PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
                observed=False,
            )
    return replay(ledger.prefix)


def _record_check(
    projection: ProjectionState,
    states: object,
    history: tuple[DeliverableSnapshot, ...],
    frontier: int,
) -> tuple[DeliverableAssessment, tuple[DeliverableSnapshot, ...]]:
    """Run the check's assessment and keep its states as the next check's history (ADR-045)."""

    assessment = assess_deliverables(projection, states, history=history)  # type: ignore[arg-type]
    event = event_id(f"evt_00000000-0000-4000-8000-{frontier:012d}")
    return assessment, (
        *history,
        *(DeliverableSnapshot(state, event, frontier) for state in assessment.states),
    )


def test_formal_crypto_new_deliverable_emptied_after_resolution(tmp_path: Path) -> None:
    """tb4n2 formal-crypto S: solve.sage written (14.9 KB), resolved, then ``write_bytes(b'')``.

    ADR-045: the second check proves earlier content from the first check's recorded reading
    (the file is new, so the task base cannot), and the lineage names that reading.
    """

    repository = _repository(tmp_path, {"README.md": "Task\n"})
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    deliverable = repository / "solve.sage"
    deliverable.write_text("x = 1\n" * 2_500, encoding="utf-8")
    projection = _resolved(os.fspath(deliverable))
    states = _states(repository, base, projection)
    assert states[(_OBLIGATION, 0)].size_bytes == 15_000  # type: ignore[attr-defined]
    # A new (untracked) file gets a line count too: that is what makes a stub detectable.
    assert states[(_OBLIGATION, 0)].lines == 2_500  # type: ignore[attr-defined]
    first, history = _record_check(projection, states, (), 10)
    assert first.emptied == ()
    assert [(item.size_bytes, item.lines, item.basis) for item in first.states] == [
        (15_000, 2_500, "delivered")
    ]

    deliverable.write_bytes(b"")
    states = _states(repository, base, projection)
    assert states[(_OBLIGATION, 0)].size_bytes == 0  # type: ignore[attr-defined]
    second, history = _record_check(projection, states, history, 20)
    assert second.emptied == ((_OBLIGATION, 0),)
    (record,) = second.states
    assert (record.change, record.proof) == ("emptied", "earlier_check")
    assert (record.prior_size_bytes, record.prior_lines, record.prior_frontier) == (
        15_000,
        2_500,
        10,
    )

    # A one-line stand-in is still a withdrawal of a 2,500-line deliverable ...
    deliverable.write_text("x = 1\n", encoding="utf-8")
    stub, history = _record_check(projection, _states(repository, base, projection), history, 25)
    assert stub.emptied == ((_OBLIGATION, 0),)
    # ... and restoring the deliverable clears the fact at the next check.
    deliverable.write_text("x = 1\n" * 2_500, encoding="utf-8")
    third, _history = _record_check(projection, _states(repository, base, projection), history, 30)
    assert third.emptied == ()


def test_a_deliverable_created_empty_is_never_emptied(tmp_path: Path) -> None:
    """tb4n3 cargo D/S: ``apt-packages.txt`` is created empty because the code needs no packages."""

    repository = _repository(tmp_path, {"README.md": "Task\n"})
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    deliverable = repository / "apt-packages.txt"
    deliverable.write_bytes(b"")
    projection = _resolved(os.fspath(deliverable))
    history: tuple[DeliverableSnapshot, ...] = ()
    for frontier in (10, 20, 30):
        assessment, history = _record_check(
            projection, _states(repository, base, projection), history, frontier
        )
        assert assessment.emptied == ()
        assert [item.change for item in assessment.states] == [None]


def test_a_new_deliverable_cut_to_a_stub_is_truncated(tmp_path: Path) -> None:
    """tb4n3 C5: a 300-line new (untracked) solve.sage cut to one stub line was never caught."""

    repository = _repository(tmp_path, {"README.md": "Task\n"})
    base = GitChangeCaptureAdapter().read_task_base(os.fspath(repository))
    deliverable = repository / "solve.sage"
    deliverable.write_text("x = 1\n" * 300, encoding="utf-8")
    projection = _resolved(os.fspath(deliverable))
    _first, history = _record_check(projection, _states(repository, base, projection), (), 10)
    deliverable.write_text("# placeholder\n", encoding="utf-8")
    second, _history = _record_check(projection, _states(repository, base, projection), history, 20)
    assert second.emptied == ((_OBLIGATION, 0),)
    assert second.states[0].change == "truncated"


def test_a_tracked_deliverable_truncated_in_place_is_emptied(tmp_path: Path) -> None:
    from finishup.kernel.delivered_set import emptied_declared_items

    repository, base = _cracker(tmp_path)
    (repository / "cracker.py").write_text("def crack(): ...\n", encoding="utf-8")
    projection = _resolved("cracker.py")
    states = _states(repository, base, projection)
    assert emptied_declared_items(projection, states) == ((_OBLIGATION, 0),)  # type: ignore[arg-type]


def test_a_symlinked_deliverable_reports_no_size(tmp_path: Path) -> None:
    repository = _repository(tmp_path, {"README.md": "Task\n"})
    (tmp_path / "elsewhere").write_bytes(b"")
    (repository / "out.txt").symlink_to(tmp_path / "elsewhere")
    probes = GitChangeCaptureAdapter().probe_requested_paths(os.fspath(repository), ("out.txt",))
    assert probes[0].size_bytes is None
