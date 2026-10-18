"""The shell-write parser (ADR-045, tb4n3 RC-5, issue #1028): paths, scopes, bounds, honesty.

Provenance: the independent Codex review of the round-3 lexer (``codex_review_4``) found four
regressions and a set of inherited defects, each with an exact command. Every one of those
commands is a vector in ``builders.shell_write_vectors`` with the paths and scopes the review
named as right; the hook and Codex-stream callers read the same table in their own tests.
A false write tells the agent its verification is stale and a missed write hides an edit made
after it, so when the parser cannot be sure it names no write.
"""

from __future__ import annotations

import shlex
import time
from collections.abc import Sequence

import pytest

from builders.shell_write_vectors import VECTORS, ShellWriteVector
from finishup.domain import shell_writes
from finishup.domain.observation import (
    _MAX_OBSERVED_COMMAND_CHARS,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.shell_writes import MAX_SHELL_WRITE_CHARS, shell_write_paths, shell_write_scope

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

    def spy(text: str, *, partial: bool) -> object:
        seen.append(len(text))
        return real(text, partial=partial)

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
    ("nested arithmetic", "echo " + "$((" * 4_000),
    ("many case words", "echo $(" + "case x " * 2_000),
    ("continued heredoc", "cat <<EOF\n" + "x\\\n" * 5_000 + "EOF"),
    ("many heredocs in a group", "echo $(" + "cat <<A\nx\nA\n" * 1_500 + ")"),
    ("many comments in a group", "echo $(" + "# ) \n" * 3_000 + ")"),
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


def test_a_long_heredoc_inside_the_recorded_bash_wrapper_still_names_its_file() -> None:
    """Review round 1 (9): the rollout records ``/bin/bash -lc '<script>'``, so the cap cuts
    inside the outer quoted argument; the stream must still see the write."""

    body = "x\n" * 10_000
    for script in (
        "cat > solution.py <<'EOF'\n" + body + "EOF",
        "cd /app && cat > /app/solution.py <<'EOF'\n" + body + "EOF",
    ):
        command = shlex.join(["/bin/bash", "-lc", script])
        assert len(command) > MAX_SHELL_WRITE_CHARS
        assert len(shell_write_paths(command)) == 1
        assert shell_write_paths(command)[0].endswith("solution.py")
        assert shell_write_scope(command, workspace="/app", inside=_inside) == "workspace"
    relative = shlex.join(["/bin/bash", "-lc", "cat > solution.py <<'EOF'\n" + body + "EOF"])
    scope = shell_write_scope(
        relative, workspace=None, inside=lambda _path: False, relative_only=True
    )
    assert scope == "workspace"


def test_a_write_after_the_cap_is_not_seen_and_a_cut_command_is_never_guessed() -> None:
    padding = "# " + "p" * 80 + "\n"
    command = padding * 300 + "echo done > late.txt\n"
    assert len(command) > MAX_SHELL_WRITE_CHARS
    assert shell_write_paths(command) == []
    # Whole lines before the cut are read; the line the cut interrupts is dropped, so a path can
    # never be a truncated prefix of the real one.
    head = "echo x > early.txt\n"
    assert shell_write_paths(head + "echo y > " + "z" * MAX_SHELL_WRITE_CHARS) == ["early.txt"]
    assert shell_write_paths(head + "echo y \\\n" + "z" * MAX_SHELL_WRITE_CHARS) == ["early.txt"]


@pytest.mark.parametrize(
    ("command", "paths"),
    [
        # Review round 1 (10): a multi-line quote the cut leaves open erases nothing before it.
        (": > early\nprintf 'hello\n" + "p" * 16_384 + "'", ["early"]),
        (": > early\ncp src dest '\n" + "p" * 16_384 + "'", ["early"]),
        (": > early\necho x > '\n" + "p" * 16_384 + "'", ["early"]),
        (': > early\necho "a\n' + "p" * 16_384 + '"', ["early"]),
        # A backslash in a comment, or an escaped backslash, continues no line.
        (": > out; # \\\n" + "p" * 16_384, ["out"]),
        (": > out \\\\\n" + "p" * 16_384, ["out"]),
        # A line really continued past the cut is incomplete: its command is dropped.
        (": > early\ncp src dest \\\n" + "p" * 16_384, ["early"]),
        # An expansion the cut leaves open.
        (": > early\necho $(cat <<EOF\n" + "p" * 16_384 + "\nEOF\n)", ["early"]),
        # Review round 2 (1): a redirect of the command the cut interrupted is not a write either.
        (": > ghost '\n" + "x" * 17_000, []),
        (": > early\n: > ghost '\n" + "x" * 17_000, ["early"]),
        (': > early\ncp a ghost "\n' + "x" * 17_000, ["early"]),
    ],
)
def test_the_cut_keeps_what_precedes_it(command: str, paths: list[str]) -> None:
    assert len(command) > MAX_SHELL_WRITE_CHARS
    assert shell_write_paths(command) == paths


@pytest.mark.parametrize(
    ("script", "paths"),
    [
        (": > ghost '\n" + "x" * 17_000, []),
        (": > early\n: > ghost '\n" + "x" * 17_000, ["early"]),
    ],
)
def test_the_cut_inside_the_recorded_bash_wrapper_keeps_what_precedes_it(
    script: str, paths: list[str]
) -> None:
    command = shlex.join(["/bin/bash", "-lc", script])
    assert len(command) > MAX_SHELL_WRITE_CHARS
    assert shell_write_paths(command) == paths


def test_a_write_in_a_nested_shell_is_seen_through_the_recorded_wrapper_too() -> None:
    """The rollout wraps the agent's own ``bash -c`` once more than the hook sees it."""

    inner = shlex.join(["bash", "-c", shlex.join(["bash", "-c", "cat > solve.py"])])
    assert shell_write_paths(inner) == ["solve.py"]
    assert shell_write_paths(shlex.join(["/bin/bash", "-lc", inner])) == ["solve.py"]


def test_wrapper_stripping_never_sees_more_than_a_constant_number_of_words(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``strip_wrappers`` shifts a list per wrapper option; the parser hands it a bounded head."""

    seen: list[int] = []
    real = shell_writes.strip_wrappers

    def spy(words: Sequence[str]) -> list[str]:
        seen.append(len(words))
        return real(words)

    monkeypatch.setattr(shell_writes, "strip_wrappers", spy)
    assert shell_write_paths("env " + "- " * 8_000 + "touch out") == []  # too many to tell
    assert shell_write_paths("timeout " + "-v " * 5_000 + "cp a b") == []
    assert shell_write_paths("cp " + "a " * 8_000 + "b") == ["b"]
    assert seen
    assert max(seen) <= 128


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


@pytest.mark.parametrize(
    "name",
    [
        "finishup_receipt.md",
        "yoetz_receipt.md",
        "/app/output/yoetz_receipt.json",
        "YOETZ-export.txt",
    ],
)
def test_a_receipt_saved_under_either_product_name_is_finishup_material(name: str) -> None:
    """Agents guided before the rename save ``yoetz_receipt.md``; it is classified alike (ADR-048)."""

    command = f": > {name}"
    assert shell_write_scope(command, workspace="/app", inside=_inside) == "yoetz_owned"
    if not name.startswith("/"):
        assert (
            shell_write_scope(
                command, workspace=None, inside=lambda _path: False, relative_only=True
            )
            == "yoetz_owned"
        )
    # Two non-counting classes still count as an edit, whichever spelling names the receipt.
    assert shell_write_scope(f": > NOTES.md; {command}", workspace="/app", inside=_inside) == (
        "workspace"
    )


# --- n7 RC2(a): heredoc-fed patches name the files they write (#1106) --------------------------

_DIFF = "--- a/src/x.py\n+++ b/src/x.py\n@@\n-it's\n+ok\n"


@pytest.mark.parametrize(
    ("command", "paths"),
    [
        ("apply_patch <<'P'\n*** Begin Patch\n*** Update File: a.py\n*** End Patch\nP", ("a.py",)),
        (
            "applypatch <<'P'\n*** Add File: n.py\n*** Update File: o.py\n*** Move to: m.py\nP",
            ("n.py", "o.py", "m.py"),
        ),
        (f"cd /app && git apply <<'EOF'\n{_DIFF}EOF\npytest -q", ("src/x.py",)),
        (f"git apply -p1 --3way - <<'EOF'\n{_DIFF}EOF", ("src/x.py",)),
        (f"git apply -p0 <<'EOF'\n{_DIFF}EOF", ("b/src/x.py",)),
        (f"patch -p1 <<'EOF'\n{_DIFF}EOF", ("src/x.py",)),
        (f"patch -p 0 -N <<'EOF'\n{_DIFF}EOF", ("b/src/x.py",)),
        (f"patch <<'EOF'\n{_DIFF}EOF", ("src/x.py",)),
        ("git apply <<'EOF'\n--- a/README.md\n+++ /dev/null\n@@\n-x\nEOF", ("README.md",)),
        ("git apply <<'EOF'\n--- /dev/null\n+++ b/new.py\n@@\n+x\nEOF", ("new.py",)),
        ("git apply <<'EOF'\n--- /tmp/a\t2026-01-01\n+++ /tmp/a\t2026-01-02\nEOF", ("tmp/a",)),
        ("patch -p0 <<'EOF'\n--- /tmp/a\n+++ /tmp/a\nEOF", ("/tmp/a",)),
        (
            # A removed ``-- note`` and an added ``++ n`` body line are not file headers.
            "git apply <<'EOF'\n--- a/q.sql\n+++ b/q.sql\n@@\n--- note\n+x\n+++ n\nEOF",
            ("q.sql",),
        ),
    ],
)
def test_heredoc_patch_paths_reads_three_patch_forms(command: str, paths: tuple[str, ...]) -> None:
    """n7 RC2(a): the patch's file headers are the write; the command's tokens show none."""

    assert shell_writes.heredoc_patch_paths(command) == paths


@pytest.mark.parametrize(
    "command",
    [
        f"git apply --check <<'EOF'\n{_DIFF}EOF",
        f"git apply --stat <<'EOF'\n{_DIFF}EOF",
        f"git apply --cached <<'EOF'\n{_DIFF}EOF",
        f"git apply --directory=sub <<'EOF'\n{_DIFF}EOF",
        f"git apply fix.patch <<'EOF'\n{_DIFF}EOF",
        f"patch --dry-run -p1 <<'EOF'\n{_DIFF}EOF",
        f"patch -C -p1 <<'EOF'\n{_DIFF}EOF",
        f"patch -p1 -i fix.patch <<'EOF'\n{_DIFF}EOF",
        f"patch -p1 -o out.py <<'EOF'\n{_DIFF}EOF",
        f"patch -d sub -p1 <<'EOF'\n{_DIFF}EOF",
        f"patch -p1 src/x.py <<'EOF'\n{_DIFF}EOF",
        f"cat <<'EOF'\n{_DIFF}EOF",
        f"git apply <<'EOF'\n{_DIFF}",  # unterminated: not a complete edit
        'git apply <<\'EOF\'\n--- "a/sp ace"\n+++ "b/sp ace"\nEOF',
        f"git apply -p5 <<'EOF'\n{_DIFF}EOF",  # fewer components than the strip
    ],
)
def test_heredoc_patch_paths_names_nothing_it_cannot_place(command: str) -> None:
    assert shell_writes.heredoc_patch_paths(command) == ()


@pytest.mark.parametrize(
    ("command", "intercepted"),
    [
        ("apply_patch <<'EOF'\n*** Begin Patch\n*** End Patch\nEOF", True),
        ("apply_patch <<'EOF'\n*** Begin Patch\n*** End Patch\nEOF\n", True),
        ("applypatch <<EOF\n*** Begin Patch\n*** End Patch\nEOF", True),
        ("cd /app && apply_patch <<'EOF'\n*** End Patch\nEOF", True),
        ("cd '/my app' && apply_patch <<'EOF'\n*** End Patch\nEOF", True),
        ("apply_patch <<'EOF'\n*** End Patch\nEOF\npytest -q", False),
        ("apply_patch <<'EOF' && pytest -q\n*** End Patch\nEOF", False),
        ("echo hi; apply_patch <<'EOF'\n*** End Patch\nEOF", False),
        ("cd -P /app && apply_patch <<'EOF'\n*** End Patch\nEOF", False),
        ("cd /app || apply_patch <<'EOF'\n*** End Patch\nEOF", False),
        ("apply_patch x <<'EOF'\n*** End Patch\nEOF", False),
        ("apply_patch <<'EOF'\n*** End Patch\n", False),
        ("git apply <<'EOF'\n--- a/x\n+++ b/x\nEOF", False),
    ],
)
def test_codex_intercepts_only_a_sole_shell_apply_patch(command: str, intercepted: bool) -> None:
    """Codex 0.159 ``invocation.rs``: only a script that is that one statement is intercepted."""

    assert shell_writes.codex_intercepts_shell_apply_patch(command) is intercepted


# --- n7 RC2(c): a shell write of only project documentation is ``docs`` (#1106) ----------------


@pytest.mark.parametrize(
    ("command", "scope"),
    [
        ("cat > README.md <<'EOF'\n# Title\nEOF", "docs"),
        ("echo '- fix' >> CHANGELOG.md", "docs"),
        ("sed -i 's/a/b/' docs/guide.md", "docs"),
        ("cat > README.md <<'EOF'\nx\nEOF\necho y > src/app.py", "workspace"),
        ("echo x > README.md; echo y > NOTES.md", "workspace"),
        ("cp a.md docs/", "workspace"),  # a directory destination is classified by location
        ("echo x > tests/fixtures/expected.md", "workspace"),
    ],
)
def test_a_shell_write_of_only_docs_is_docs(command: str, scope: str) -> None:
    assert shell_write_scope(command, workspace="/app", inside=_inside) == scope


def test_a_heredoc_patch_of_only_docs_is_docs() -> None:
    command = "git apply <<'EOF'\n--- a/README.md\n+++ b/README.md\n@@\n-a\n+it's\nEOF"
    assert shell_write_scope(
        command,
        workspace="/app",
        inside=_inside,
        also_written=shell_writes.heredoc_patch_paths(command),
    ) == ("docs")


_PATCH = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+it's\n"


@pytest.mark.parametrize(
    "command",
    [
        # A long blank run between two separators before ``<<`` (quadratic under a regex search).
        ";" + " " * 500_000 + ";git apply <<EOF\n" + _PATCH + "EOF\npytest -q\n",
        "echo a;" + " " * 32_000 + ";git apply <<EOF\n" + _PATCH + "EOF\npytest -q\n",
        "git apply " + "-v " * 200_000 + "<<EOF\n" + _PATCH + "EOF\n",
        "<<  " * 100_000 + "\n",
        "git apply <<'EOF'\n" + _PATCH * 20_000 + "EOF\npytest -q\n",
    ],
    ids=["blank-run", "blank-run-32k", "long-invocation", "many-heredoc-starts", "long-patch"],
)
def test_heredoc_patch_readers_are_linear(command: str) -> None:
    """Every heredoc patch reader is fast on a megabyte-sized command (#1106 r1)."""

    started = time.perf_counter()
    shell_writes.heredoc_patch_paths(command)
    shell_writes.codex_intercepts_shell_apply_patch(command)
    assert time.perf_counter() - started < _DEADLINE_SECONDS


def test_a_long_patch_past_the_token_bound_is_still_a_write() -> None:
    command = "git apply <<'EOF'\n" + "+" * (MAX_SHELL_WRITE_CHARS + 10) + "\n" + _PATCH + "EOF\n"
    assert shell_writes.heredoc_patch_paths(command) == ("x.py",)


@pytest.mark.parametrize(
    ("script", "paths"),
    [
        ("git apply <<'EOF'\n" + _PATCH + "EOF\npytest -q", ("x.py",)),
        ("git apply <<EOF\n" + _PATCH + "EOF\npytest -q", ("x.py",)),
        (
            "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: src/a.py\n@@\n-a\n+it's\n"
            "*** End Patch\nEOF\npytest -q",
            ("src/a.py",),
        ),
        ("patch -p1 <<'EOF'\n" + _PATCH + "EOF", ("x.py",)),
    ],
)
def test_a_joined_native_argv_names_its_heredoc_patch(script: str, paths: tuple[str, ...]) -> None:
    """A Codex ``CommandExecution`` command is ``['/bin/bash', '-lc', CMD]`` (#1106 r1)."""

    for shell in ("/bin/bash", "bash", "/bin/zsh", "sh"):
        joined = shlex.join([shell, "-lc", script])
        assert shell_writes.heredoc_patch_paths(joined) == paths
        assert (
            shell_write_scope(
                joined,
                workspace=None,
                inside=lambda _path: False,
                relative_only=True,
                also_written=shell_writes.heredoc_patch_paths(joined),
            )
            == "workspace"
        )
    # A quoted heredoc in an argument that is not a host shell's script stays unread.
    assert shell_writes.heredoc_patch_paths(shlex.join(["echo", script])) == ()
