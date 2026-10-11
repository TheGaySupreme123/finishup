"""The shell-write parser (ADR-045, tb4n3 RC-5, issue #1028): paths, scopes, bounds, honesty.

Provenance: the independent Codex review of the round-3 lexer (``codex_review_4``) found four
regressions and a set of inherited defects, each with an exact command. Every one of those
commands is a vector in ``builders.shell_write_vectors`` with the paths and scopes the review
named as right; the hook and Codex-stream callers read the same table in their own tests.
A false write tells the agent its verification is stale and a missed write hides an edit made
after it, so when the parser cannot be sure it names no write.
"""

from __future__ import annotations

import time

import pytest

from builders.shell_write_vectors import VECTORS, ShellWriteVector
from yoetz.domain import shell_writes
from yoetz.domain.observation import (
    _MAX_OBSERVED_COMMAND_CHARS,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.domain.shell_writes import MAX_SHELL_WRITE_CHARS, shell_write_paths, shell_write_scope

_DEADLINE_SECONDS = 2.0


def _inside(path: str) -> bool:
    return path == "/app" or path.startswith("/app/")


def _ids(vectors: list[ShellWriteVector]) -> list[str]:
    return [f"{index:03d}-{vector.source}" for index, vector in enumerate(vectors)]


@pytest.mark.parametrize("vector", VECTORS, ids=_ids(VECTORS))
def test_the_exact_commands_name_the_paths_the_review_calls_right(
    vector: ShellWriteVector,
) -> None:
    assert shell_write_paths(vector.command) == vector.paths


@pytest.mark.parametrize("vector", VECTORS, ids=_ids(VECTORS))
def test_the_exact_commands_earn_the_scope_of_the_hook_and_of_the_stream(
    vector: ShellWriteVector,
) -> None:
    hook = shell_write_scope(vector.command, workspace="/app", inside=_inside)
    assert hook == vector.hook
    stream = shell_write_scope(
        vector.command, workspace=None, inside=lambda _path: False, relative_only=True
    )
    assert stream == vector.stream


def test_the_cap_is_the_hooks_normalization_limit() -> None:
    """``domain.observation`` cannot be imported for its private constant; this pins the copy."""

    assert MAX_SHELL_WRITE_CHARS == _MAX_OBSERVED_COMMAND_CHARS == 16_384


# --- bounds -----------------------------------------------------------------------------------


def _timed(command: str) -> tuple[list[str], float]:
    started = time.perf_counter()
    paths = shell_write_paths(command)
    return paths, time.perf_counter() - started


def test_the_sed_in_place_backtracking_input_is_bounded_and_fast() -> None:
    """Review 5: ``"sed -" + "i" * 64000 + "! solve.py"`` took 9 s in ``_SED_IN_PLACE``."""

    for size in (32_000, 64_000):
        paths, elapsed = _timed("sed -" + "i" * size + "! solve.py")
        assert paths == []
        assert elapsed < _DEADLINE_SECONDS
    # Inside the cap the same shape is linear too, and the option is simply not in place.
    paths, elapsed = _timed("sed -" + "i" * 16_000 + "! solve.py")
    assert paths == []
    assert elapsed < _DEADLINE_SECONDS


def test_the_parser_never_reads_more_than_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """The deterministic proof of the bound: no matter the input, the lexer sees at most the cap."""

    seen: list[int] = []
    real = shell_writes._lex  # pyright: ignore[reportPrivateUsage]

    def spy(text: str) -> object:
        seen.append(len(text))
        return real(text)

    monkeypatch.setattr(shell_writes, "_lex", spy)
    shell_write_paths("echo x > a.txt\n" * 200_000)
    shell_write_paths("cat > f <<'EOF'\n" + "line\n" * 100_000 + "EOF")
    shell_write_paths("bash -lc '" + "echo x > a.txt; " * 5_000 + "'")
    assert seen
    assert max(seen) <= MAX_SHELL_WRITE_CHARS


_ADVERSARIAL: list[tuple[str, str]] = [
    ("nested substitutions", "echo " + "$(" * 8_000),
    ("nested quoted substitutions", 'echo "' + "$(" * 2_500 + ")" * 2_500 + '"'),
    ("many quotes", "echo " + "'a' " * 4_000),
    ("many bangs", "! " * 8_000 + "cp a b"),
    ("many wrapper options", "timeout " + "-v " * 5_000 + "cp a b"),
    ("many words", "cp " + "a " * 8_000 + "b"),
    ("many redirects", "echo x " + "> f ; " * 2_500),
    ("many heredocs", "cat " + "<<A " * 3_000),
    ("many backslashes", "echo " + "\\\\" * 8_000),
    ("many arithmetic", "((" * 4_000),
    ("deep wrappers", "bash -c " * 1_000),
]


@pytest.mark.parametrize(("name", "command"), _ADVERSARIAL, ids=[name for name, _ in _ADVERSARIAL])
def test_adversarial_input_inside_and_beyond_the_cap_is_fast_and_never_raises(
    name: str, command: str
) -> None:
    for text in (command[:MAX_SHELL_WRITE_CHARS], command * 8, command + "\n" + command):
        paths, elapsed = _timed(text)
        assert isinstance(paths, list), name
        assert elapsed < _DEADLINE_SECONDS, name


def test_a_megabyte_of_one_line_is_not_analysed_and_not_blocked() -> None:
    paths, elapsed = _timed("echo " + "a" * (1 << 20) + " > f")
    assert paths == []  # no complete line fits the cap: no guess
    assert elapsed < _DEADLINE_SECONDS


def test_a_long_heredoc_body_still_names_the_file_it_writes() -> None:
    """8 of the 9 recorded commands over the cap are ``cat > solution <<'EOF'`` bodies."""

    body = "x = 1\n" * 10_000
    command = f"mkdir -p out && cat > out/solution.py <<'EOF'\n{body}EOF\n"
    assert len(command) > MAX_SHELL_WRITE_CHARS
    assert shell_write_paths(command) == ["out/solution.py"]
    assert shell_write_scope(command, workspace="/app", inside=_inside) == "workspace"


def test_a_write_after_the_cap_is_not_seen_and_a_cut_line_is_never_guessed() -> None:
    padding = "# " + "p" * 80 + "\n"
    command = padding * 300 + "echo done > late.txt\n"
    assert len(command) > MAX_SHELL_WRITE_CHARS
    assert shell_write_paths(command) == []
    # The last complete line inside the cap is analysed; a line cut by the cap is dropped whole,
    # so a path can never be a truncated prefix of the real one.
    head = "echo x > early.txt\n"
    cut = head + "echo y > " + "z" * MAX_SHELL_WRITE_CHARS
    assert shell_write_paths(cut) == ["early.txt"]
    # A line continued past the cap is not complete either.
    continued = head + "echo y \\\n" + "z" * MAX_SHELL_WRITE_CHARS
    assert shell_write_paths(continued) == ["early.txt"]


# --- honesty: no guessed write ------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        'echo "$(',
        "echo `",
        "echo $'unterminated",
        "echo ${",
        "echo ((",
        "echo \\",
        "cat > ",
        "cat <<",
        ">",
        "cp",
        "cp a",
        "sed -i",
        "sed -i s/a/b/",
        "tee",
        "touch",
        "dd of=",
        "install -d",
        "$(echo > a.txt)",
        "echo x > $(echo a.txt)",
        "echo x > `echo a.txt`",
        "echo x > $'a.txt'",
    ],
)
def test_a_command_the_parser_cannot_be_sure_of_names_no_write(command: str) -> None:
    assert shell_write_paths(command) == []
    assert shell_write_scope(command, workspace="/app", inside=_inside) is None


def test_the_same_path_is_named_once_and_in_order() -> None:
    assert shell_write_paths("echo a > b.txt; echo c >> b.txt; touch a.txt b.txt") == [
        "b.txt",
        "a.txt",
    ]
