"""Whether a process a call started still runs in the workspace (PR #1080 round 6, finding 2).

The decision logic is exercised over synthetic process tables; the platform readers are exercised
against this machine's real process table with a pipe-controlled child, with bounded waits only.
"""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from builders.process_reaping import not_a_child_subreaper
from finishup.adapters import process_lifetime
from finishup.adapters.process_lifetime import (
    PROCESS_CLOCK_SLACK_NS,
    _candidates,
    _chain,
    _owned_roots,
    _parse_linux_stat,
    _Process,
    lingering_process,
    process_clock_ns,
)

_WINDOW = 1_000_000_000_000


def _table() -> dict[int, _Process]:
    before = _WINDOW - 10 * PROCESS_CLOCK_SLACK_NS
    during = _WINDOW + 1_000
    return {
        # The host (started before the window) and the hook chain it launched during it.
        100: _Process(1, before, False),
        200: _Process(100, during, False),  # sh -c hook
        300: _Process(200, during, False),  # this hook process
        # The host's other in-window work: a parallel hook and its grandchild, a parallel tool.
        210: _Process(100, during, False),
        211: _Process(210, during, False),
        220: _Process(100, during, False),
        # A child a finished command left behind, reparented to init, and its own child.
        400: _Process(1, during, False),
        401: _Process(400, during, False),
        # An orphan that predates the window, and a zombie from it.
        500: _Process(1, before, False),
        600: _Process(1, during, True),
    }


def test_the_host_and_its_descendants_are_owned_and_escaped_children_are_candidates() -> None:
    table = _table()
    chain = _chain(300, table, None)
    assert [pid for pid, _process in chain] == [300, 200, 100]
    owned = _owned_roots(chain, _WINDOW)
    assert owned == frozenset({300, 200, 100})
    assert sorted(_candidates(table, _WINDOW, owned)) == [400, 401]


def test_in_a_test_process_the_process_itself_is_the_host() -> None:
    table = {
        50: _Process(1, _WINDOW - 10**9, False),
        51: _Process(50, _WINDOW + 5, False),  # a helper the test itself still parents
        52: _Process(1, _WINDOW + 5, False),  # an escaped child
    }
    owned = _owned_roots(_chain(50, table, None), _WINDOW)
    assert owned == frozenset({50})
    assert list(_candidates(table, _WINDOW, owned)) == [52]


def test_the_slack_counts_processes_started_just_before_the_window() -> None:
    table = {
        10: _Process(1, _WINDOW - 10**9, False),
        20: _Process(1, _WINDOW - PROCESS_CLOCK_SLACK_NS + 1, False),
        30: _Process(1, _WINDOW - PROCESS_CLOCK_SLACK_NS - 1, False),
    }
    assert list(_candidates(table, _WINDOW, frozenset({10}))) == [20]


def test_a_linux_stat_line_parses_even_with_a_hostile_command_name() -> None:
    tail = " ".join(["S", "4242", *["0"] * 17, "12345"])
    raw = f"77 (we ) ird (name) {tail} 0 0".encode()
    parsed = _parse_linux_stat(raw, 10_000_000.0)
    assert parsed == _Process(4242, 123_450_000_000, False)
    zombie = _parse_linux_stat(f"77 (z) {tail.replace('S', 'Z', 1)}".encode(), 1.0)
    assert zombie is not None and zombie.zombie
    assert _parse_linux_stat(b"garbage", 1.0) is None
    assert _parse_linux_stat(b"1 (x) S 2", 1.0) is None


def test_an_unsupported_platform_cannot_establish_an_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    # Only this module's view of the platform changes; the interpreter's ``sys`` is untouched.
    monkeypatch.setattr(process_lifetime, "sys", SimpleNamespace(platform="sunos5"))
    assert process_clock_ns() is None
    assert lingering_process(1, "/") is None


def _readable() -> bool:
    window = process_clock_ns()
    return window is not None and lingering_process(window, "/nonexistent-root") is False


@pytest.mark.skipif(not _readable(), reason="no readable process table here")
@pytest.mark.parametrize("where", ["cwd", "open_for_write", "elsewhere", "open_for_read"])
def test_a_real_escaped_child_lingers_by_its_directory_or_written_file(
    tmp_path: Path, where: str
) -> None:
    import select

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "log.txt").write_text("")
    outside = tmp_path / "outside"
    outside.mkdir()
    mode = {"open_for_write": "a", "open_for_read": "r"}.get(where)
    worker = (
        "import os, sys\n"
        + (f"handle = open({str(workspace / 'log.txt')!r}, {mode!r})\n" if mode else "")
        + "os.write(int(sys.argv[2]), b'R')\n"
        + "os.read(int(sys.argv[1]), 1)\n"
    )
    launcher = (
        "import subprocess, sys\n"
        "subprocess.Popen([sys.executable, '-c', sys.argv[1], *sys.argv[2:]],"
        " pass_fds=tuple(int(v) for v in sys.argv[2:]), start_new_session=True,"
        " stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
    )
    window = process_clock_ns()
    assert window is not None
    release_read, release_write = os.pipe()
    ready_read, ready_write = os.pipe()
    with not_a_child_subreaper():
        subprocess.run(
            [sys.executable, "-c", launcher, worker, str(release_read), str(ready_write)],
            cwd=workspace if where == "cwd" else outside,
            pass_fds=(release_read, ready_write),
            check=True,
        )
        os.close(release_read)
        os.close(ready_write)
        try:
            ready, _write, _error = select.select([ready_read], [], [], 30)
            assert ready and os.read(ready_read, 1) == b"R"
            answer = lingering_process(window, str(workspace))
        finally:
            os.write(release_write, b"G")
            os.close(release_write)
            os.close(ready_read)
    assert answer is (where in {"cwd", "open_for_write"})
