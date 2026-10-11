"""Canonical command argv and commitments, and the write scopes of shell commands (ADR-045).

tb4n3 RC-5: a planned verification used to match only an identical command, so ``timeout 3000
python3 x.py`` never matched ``python x.py``, a task-quoted flag set never matched the real
compile, and ``python -m pytest`` never matched ``pytest``. These tests lock the reductions
(wrappers, interpreter aliases, ``python -m pytest``), their limits (arguments are never
reordered or rewritten, so different commands never share a form) and the three kinds of
commitment a hook sends.
"""

from __future__ import annotations

import pytest

from yoetz.cli.runtime_facts import runtime_structural_facts
from yoetz.domain.command_segments import (
    CANONICAL_KINDS,
    MAX_CANONICAL_COMMITMENTS,
    MAX_COMMAND_COMMITMENTS,
    MAX_SEGMENT_COMMITMENTS,
    canonical_command_commitments,
    canonical_commitment,
    canonical_words,
    command_segment_commitments,
    command_structure,
    planned_segments,
)
from yoetz.domain.observation import (
    _MAX_COMMAND_SEGMENT_COMMITMENTS,  # pyright: ignore[reportPrivateUsage]
    normalize_observed_command,
)
from yoetz.domain.shell_writes import shell_write_paths, shell_write_scope
from yoetz.domain.write_scope import classify_write_path, edit_write_scope, notes_artifact_name

_KEY = b"k" * 32


def test_the_hook_bound_is_the_domain_bound() -> None:
    """``domain.observation`` cannot import ``command_segments``; this pins its copy."""

    assert _MAX_COMMAND_SEGMENT_COMMITMENTS == MAX_COMMAND_COMMITMENTS
    assert MAX_COMMAND_COMMITMENTS == MAX_SEGMENT_COMMITMENTS + MAX_CANONICAL_COMMITMENTS


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["python3", "/app/x.py"], ("python", "/app/x.py")),
        (["/usr/bin/python3.11", "-u", "x.py"], ("python", "x.py")),
        (["timeout", "3000", "python", "x.py"], ("python", "x.py")),
        (["timeout", "-k", "5", "--foreground", "10m", "pytest", "-q"], ("pytest", "-q")),
        (["nice", "-n", "5", "pytest"], ("pytest",)),
        (["nice", "-5", "pytest"], ("pytest",)),
        (["nohup", "stdbuf", "-oL", "make", "test"], ("make", "test")),
        (["env", "FOO=1", "-u", "BAR", "pytest"], ("pytest",)),
        (["FOO=1", "BAR=2", "pytest", "-x"], ("pytest", "-x")),
        (["python", "-m", "pytest", "-q", "tests/"], ("pytest", "-q", "tests/")),
        (["python3", "-mpytest", "-q"], ("pytest", "-q")),
        (["py.test", "-q"], ("pytest", "-q")),
        (["/tmp/venv/bin/pytest", "-q"], ("pytest", "-q")),
        (["uv", "run", "--with", "numpy", "pytest", "-q"], ("pytest", "-q")),
        (["poetry", "run", "pytest"], ("pytest",)),
        (["/usr/bin/g++", "-O3", "a.cpp"], ("g++", "-O3", "a.cpp")),
        # Never rewritten: a different program, argument order and operands stay as they are.
        (["python", "-m", "unittest", "discover"], ("python", "-m", "unittest", "discover")),
        (["cp", "b", "a"], ("cp", "b", "a")),
        # ``uv run --script`` runs the agent's own script by its launcher; it is not unwrapped.
        (["uv", "run", "--script", "build_model.py"], ("uv", "run", "--script", "build_model.py")),
    ],
)
def test_canonical_words(argv: list[str], expected: tuple[str, ...]) -> None:
    assert canonical_words(argv) == expected


def test_commitments_have_three_domain_separated_kinds() -> None:
    words = ["g++", "-O3", "-std=c++17", "-I/app", "/app/solution.cpp", "-o", "/app/t"]
    full, prefixes, flags = canonical_command_commitments(_KEY, words)
    assert len(full) == 1
    # One prefix for each leading run of two or more arguments shorter than the whole.
    assert len(prefixes) == len(words) - 2
    assert len(flags) == len(words) - 1
    everything = {*full, *prefixes, *flags}
    assert len(everything) == len(full) + len(prefixes) + len(flags)
    # A kind never collides with another kind or with a segment commitment of the same text.
    text = "\x1f".join(words)
    assert {canonical_commitment(_KEY, kind, text) for kind in CANONICAL_KINDS}.isdisjoint(
        {canonical_commitment(_KEY, "prefix", "\x1f".join(words[:2]))}
    )
    with pytest.raises(ValueError):
        canonical_commitment(_KEY, "segment", text)


def test_a_single_argument_command_has_only_a_full_commitment() -> None:
    assert canonical_command_commitments(_KEY, ["pytest"]) == (
        (canonical_commitment(_KEY, "full", "pytest"),),
        (),
        (),
    )


def test_hook_commitments_for_a_wrapped_run_include_the_canonical_forms() -> None:
    normalized = normalize_observed_command("timeout 3000 python3 /app/pretrain.py")
    assert normalized is not None
    result = command_segment_commitments(_KEY, normalized)
    assert result is not None
    commitments, composition = result
    assert composition == "single"
    planned = planned_segments(_KEY, normalize_observed_command("python /app/pretrain.py") or "")
    assert planned is not None
    (probe,) = planned
    assert probe.full in commitments or probe.canonical_text in commitments


def test_a_plain_simple_command_still_adds_nothing() -> None:
    """``ls`` and ``pytest`` have no wrapper, no alias and no second argument to commit."""

    for command in ("ls", "pytest"):
        normalized = normalize_observed_command(command)
        assert normalized is not None
        assert command_segment_commitments(_KEY, normalized) is None


def test_the_canonical_budget_is_bounded_and_keeps_full_forms_first() -> None:
    commands = " && ".join(
        f"python3 step{index}.py --flag{index} value{index}" for index in range(40)
    )
    normalized = normalize_observed_command(commands)
    assert normalized is not None
    result = command_segment_commitments(_KEY, normalized)
    assert result is not None
    commitments, _composition = result
    assert len(commitments) <= MAX_COMMAND_COMMITMENTS
    assert list(commitments) == sorted(set(commitments))


def test_command_structure_names_each_simple_command_and_file_writes() -> None:
    normalized = normalize_observed_command("cd /app && pytest -q 2>&1 | tee run.log > out.txt")
    assert normalized is not None
    structure = command_structure(normalized)
    assert structure is not None
    assert [command.words[0] for command in structure.commands] == ["cd", "pytest", "tee"]
    assert structure.compound
    assert [command.writes for command in structure.commands] == [False, False, True]


# --- write scopes -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "paths"),
    [
        ("cat > solve.py <<'EOF'\nprint(1)\nEOF", ["solve.py"]),
        ("pytest -q > test.log 2>&1", ["test.log"]),
        ("sed -i 's/a/b/' src/x.py", ["src/x.py"]),
        ("sed -n 1,5p x.py", []),
        ("cp a.txt /app/b.txt && touch c", ["/app/b.txt", "c"]),
        ("echo hi | tee -a out.txt", ["out.txt"]),
        ("python gen.py > $OUT", []),
        ("ls > /dev/null", []),
        ("python - <<'PY'\nopen('x', 'w').write('y')\nPY", []),
        ("mv -t outdir a b", ["outdir"]),
        ("truncate -s 0 foo.txt", ["foo.txt"]),
    ],
)
def test_shell_write_paths(command: str, paths: list[str]) -> None:
    assert shell_write_paths(command) == paths


def test_shell_write_scope_classifies_like_an_edit_tool() -> None:
    def inside(path: str) -> bool:
        return path.startswith("/app")

    def scope(command: str) -> str | None:
        return shell_write_scope(command, workspace="/app", inside=inside)

    assert scope("cat > solve.py <<'EOF'\nx\nEOF") == "workspace"
    assert scope("cp build/out.json /app/out.json") == "workspace"
    assert scope("echo x > /etc/motd") == "outside_workspace"
    assert scope("echo x > /tmp/scratch.txt") is None
    assert scope("echo x > NOTES.md") is None
    assert scope("pytest -q") is None
    assert (
        shell_write_scope("echo x > /app/a", workspace=None, inside=inside, relative_only=True)
        is None
    )
    assert (
        shell_write_scope("echo x > a", workspace=None, inside=inside, relative_only=True)
        == "workspace"
    )


def test_notes_are_a_narrow_non_counting_class() -> None:
    assert notes_artifact_name("/app/NOTES.md")
    assert notes_artifact_name("todo.txt")
    assert not notes_artifact_name("/app/README.md")
    assert not notes_artifact_name("/app/run.log")  # a log may be the deliverable
    assert classify_write_path("/app/NOTES.md", workspace="/app", inside=True) == "notes"
    assert classify_write_path("/app/solve.py", workspace="/app", inside=True) == "workspace"
    assert edit_write_scope(["notes"]) == "notes"
    assert edit_write_scope(["notes", "workspace"]) is None
    assert edit_write_scope(["notes", "scratch"]) is None


def test_an_edit_tool_call_naming_a_notes_file_carries_the_notes_scope() -> None:
    facts = runtime_structural_facts(
        {"tool_input": {"file_path": "/app/NOTES.md"}},
        tool_name="Write",
        workspace_locator="/app",
        inside=lambda path: path.startswith("/app"),
    )
    assert facts["write_scope"] == "notes"


def test_a_shell_command_that_writes_the_workspace_carries_the_workspace_scope() -> None:
    def facts(command: str) -> dict[str, object]:
        return dict(
            runtime_structural_facts(
                {"tool_input": {"cmd": command}},
                tool_name="exec_command",
                workspace_locator="/app",
                inside=lambda path: path.startswith("/app"),
            )
        )

    assert facts("cat > solve.py <<'EOF'\nx\nEOF")["write_scope"] == "workspace"
    assert facts("echo x > /etc/motd")["write_scope"] == "outside_workspace"
    assert "write_scope" not in facts("pytest -q")
