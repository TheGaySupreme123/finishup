"""What a shell command visibly writes, and the write scope that earns it (ADR-045, tb4n3 RC-5).

``edited_after_last_verification`` and the stale-verification facts used to see only edit-tool
calls, so ``cat > solve.py <<'EOF'``, ``sed -i`` and ``cp build/out.json out.json`` changed the
work invisibly. A hook (or the Codex rollout stream) reads the command's shell tokens, never its
output or any file, and names the paths it visibly writes: a redirect target, a ``tee`` operand,
the file operands of ``sed -i``, the destination of ``cp``/``mv``/``install``/``rsync`` (the last
operand, or ``-t DIR``), ``touch``/``truncate`` operands and ``dd of=``. A write it cannot
attribute (a path built from ``$VAR`` or ``~``, a script that opens files itself) names nothing,
which only means the kernel does not count that command as an edit. Each path is classified by
the same rules as an edit tool's (``domain.write_scope``), so the answer is one rule everywhere.
Closed tokens only; no path or command text leaves this module.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from typing import Final

from yoetz.domain.command_segments import strip_wrappers, wrapped_shell_argument
from yoetz.domain.write_scope import classify_write_path, scratch_path

__all__ = ["shell_write_paths", "shell_write_scope"]

# Operators that write their next word (a redirect target) ...
_REDIRECT_OPERATORS: Final = frozenset({">", ">>", ">|", "&>", "&>>"})
# ... redirects that only read or duplicate (their next word is a source, a descriptor or a
# heredoc delimiter, never a write) ...
_OTHER_REDIRECTS: Final = frozenset({">&", "<", "<<", "<<<", "<<-", "<&", "<>"})
# ... and the operators that end one simple command and begin another.
_SEPARATORS: Final = frozenset({"&&", "||", ";", "|", "|&", "&", ";;", "(", ")", "\n"})
_OPERATOR_CHARS: Final = frozenset(";&|()<>")
_OPERATORS_LONGEST_FIRST: Final = (
    "&>>",
    "<<<",
    "<<-",
    "&&",
    "||",
    "|&",
    ";;",
    ">>",
    ">|",
    ">&",
    "&>",
    "<<",
    "<&",
    "<>",
)
_HEREDOC: Final = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")

_FILE_OPERAND_SKIP: Final = frozenset(
    {"-", "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin"}
)
_COPY_LIKE: Final = frozenset({"cp", "mv", "install", "rsync"})
_SED_NAMES: Final = frozenset({"sed", "gsed"})
_SED_IN_PLACE: Final = re.compile(r"^(?:--in-place(?:=.*)?|-[A-Za-z]*i[A-Za-z.]*)$", re.ASCII)


def _attributable(path: str) -> bool:
    """A literal path: no expansion the hook cannot resolve (``$VAR``, ``~``, globs, substitution)."""

    return (
        bool(path)
        and path not in _FILE_OPERAND_SKIP
        and not path.startswith(("~", "&", "<", ">"))
        and not any(char in path for char in "$`*?[]{}\x00\r\n")
    )


_MAX_SHELL_DEPTH: Final = 3


def _lex(text: str) -> list[tuple[str, str]] | None:
    """``(kind, text)`` tokens of *text*, ``kind`` being ``word`` or ``op``; ``None`` if unlexable.

    A purpose-built shell lexer, because a quoted or escaped operator is text and ``shlex`` cannot
    say so: in ``echo ">" f``, ``echo \\> f`` and ``echo 'a > b'`` nothing is redirected. Words
    lose their quotes and backslashes; an operator is only ever an unquoted, unescaped one;
    a newline ends a command; an unquoted ``#`` at the start of a word begins a comment; a word
    of digits directly before ``>``/``<`` is a descriptor, not an argument.
    """

    tokens: list[tuple[str, str]] = []
    buffer: list[str] = []
    in_word = False
    quoted = False
    index = 0
    size = len(text)

    def end_word() -> None:
        nonlocal in_word, quoted
        if in_word:
            tokens.append(("word", "".join(buffer)))
        buffer.clear()
        in_word = False
        quoted = False

    while index < size:
        char = text[index]
        if char in " \t\r":
            end_word()
            index += 1
        elif char == "\n":
            end_word()
            tokens.append(("op", "\n"))
            index += 1
        elif char == "\\":
            if index + 1 >= size:
                return None
            following = text[index + 1]
            if following != "\n":  # a backslash-newline joins lines
                buffer.append(following)
                in_word = True
                quoted = True
            index += 2
        elif char == "'":
            close = text.find("'", index + 1)
            if close < 0:
                return None
            buffer.append(text[index + 1 : close])
            in_word = True
            quoted = True
            index = close + 1
        elif char == '"':
            index += 1
            while True:
                if index >= size:
                    return None
                inner = text[index]
                if inner == '"':
                    index += 1
                    break
                if inner == "\\" and index + 1 < size and text[index + 1] in '"\\$`\n':
                    if text[index + 1] != "\n":
                        buffer.append(text[index + 1])
                    index += 2
                    continue
                buffer.append(inner)
                index += 1
            in_word = True
            quoted = True
        elif char == "#" and not in_word:
            while index < size and text[index] != "\n":
                index += 1
        elif char in _OPERATOR_CHARS:
            operator = next(
                (item for item in _OPERATORS_LONGEST_FIRST if text.startswith(item, index)), char
            )
            if in_word and not quoted and operator[0] in "<>" and "".join(buffer).isdigit():
                buffer.clear()
                in_word = False  # ``2>file``: the descriptor is not an argument
            end_word()
            tokens.append(("op", operator))
            index += len(operator)
        else:
            buffer.append(char)
            in_word = True
            index += 1
    end_word()
    return tokens


def _sed_files(rest: list[str]) -> list[str]:
    """The file operands of an in-place ``sed`` (the script is not one)."""

    script_given = False
    skip = False
    operands: list[str] = []
    for word in rest:
        if skip:
            skip = False
            continue
        if word in {"-e", "-f", "--expression", "--file"} or re.fullmatch(
            r"-[A-Za-hj-z]*[ef]", word
        ):
            script_given = True
            skip = True
        elif word.startswith(("--expression=", "--file=")):
            script_given = True
        elif word.startswith("-") and word != "-":
            continue
        else:
            operands.append(word)
    return operands if script_given else operands[1:]


def shell_write_paths(command: str, _depth: int = 0) -> list[str]:
    """Every path a shell command visibly writes, absolute or relative (ADR-045).

    Reads shell tokens, never output or file content: a redirect target, a ``tee`` operand, the
    file operands of ``sed -i``, the destination of ``cp``/``mv``/``install``/``rsync`` (the last
    operand, or ``-t DIR``), ``touch``/``truncate`` operands and ``dd of=``. A write the hook
    cannot attribute (a path built from ``$VAR`` or ``~``, a script that opens files itself)
    names nothing here, which only means the kernel does not count it as an edit.
    """

    lines: list[str] = []
    delimiter: str | None = None
    for line in command.split("\n"):
        if delimiter is not None:
            if line.strip() == delimiter:
                delimiter = None
            continue
        lines.append(line)
        match = _HEREDOC.search(line)
        if match is not None:
            delimiter = match.group(2)
    tokens = _lex("\n".join(lines))
    if tokens is None:
        return []
    paths: list[str] = []
    segment: list[str] = []

    def flush() -> None:
        words = strip_wrappers(segment)
        segment.clear()
        if not words:
            return
        head = os.path.basename(words[0])
        rest = words[1:]
        operands = [word for word in rest if not word.startswith("-")]
        inner = wrapped_shell_argument(words) if _depth < _MAX_SHELL_DEPTH else None
        if inner is not None:
            # ``bash -lc 'cat > f'``: the shell the host wrapped the command in runs the real one.
            paths.extend(shell_write_paths(inner, _depth + 1))
        elif head == "tee":
            paths.extend(operands)
        elif head in _SED_NAMES and any(_SED_IN_PLACE.match(word) for word in rest):
            # ``sed -i 's/a/b/' f``: the first operand is the script unless ``-e``/``-f`` gave it.
            paths.extend(_sed_files(rest))
        elif head in _COPY_LIKE:
            target = next(
                (
                    rest[index + 1]
                    for index, word in enumerate(rest[:-1])
                    if word in {"-t", "--target-directory"}
                ),
                None,
            )
            if target is not None:
                paths.append(target)
            elif len(operands) >= 2:
                paths.append(operands[-1])
        elif head in {"touch", "truncate"}:
            skip_next = False
            for word in rest:
                if skip_next:
                    skip_next = False
                    continue
                if head == "truncate" and word in {"-s", "--size", "-r", "--reference"}:
                    skip_next = True
                    continue
                if not word.startswith("-"):
                    paths.append(word)
        elif head == "dd":
            paths.extend(word[3:] for word in rest if word.startswith("of="))

    index = 0
    while index < len(tokens):
        kind, token = tokens[index]
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if kind == "op" and token in _SEPARATORS:
            flush()
        elif kind == "op" and token in _REDIRECT_OPERATORS | _OTHER_REDIRECTS:
            if following is not None and following[0] == "word":
                if token in _REDIRECT_OPERATORS:
                    paths.append(following[1])
                index += 1  # the redirect's operand is never an argument of the command
        elif kind == "word":
            segment.append(token)
        index += 1
    flush()
    return [path for path in dict.fromkeys(paths) if _attributable(path)]


def shell_write_scope(
    command: str,
    *,
    workspace: str | None,
    inside: Callable[[str], bool],
    owned_roots: tuple[str, ...] = (),
    relative_only: bool = False,
) -> str | None:
    """The ``write_scope`` a shell command earns: ``outside_workspace``, ``workspace`` or ``None``.

    Each visible write path is classified by the rules edit tools use (``domain.write_scope``):
    a real write outside the workspace wins; a write into the workspace that is not the agent's
    own notes or log, not scratch and not Yoetz-owned makes the command an edit
    (``workspace``); a command that writes only notes, Yoetz material or scratch carries that
    non-counting scope, and one that writes nothing visible claims nothing. ``relative_only`` reads only relative paths: a caller that knows no
    workspace root (the Codex rollout stream) cannot tell an absolute path inside it from one
    outside, so it claims only what a working directory makes certain.
    """

    def candidate(path: str) -> bool:
        if relative_only and path.startswith("/"):
            return False
        # The hook may consult its own environment (a ``TMPDIR`` outside the workspace is scratch
        # for this process); the kernel never does, so the answer is recorded as a closed token.
        return not (
            path.startswith("/")
            and (workspace is None or not inside(path))
            and scratch_path(path, workspace)
        )

    classes = frozenset(
        classify_write_path(
            path,
            workspace=workspace,
            inside=None if workspace is None or not path.startswith("/") else inside(path),
            owned_roots=owned_roots,
        )
        for path in shell_write_paths(command)
        if candidate(path)
    )
    if "outside_workspace" in classes:
        return "outside_workspace"
    if "workspace" in classes:
        return "workspace"
    # Only the agent's notes, Yoetz's own material or scratch: the same closed token an edit tool
    # carries, so a declared output of that kind keeps counting (``non_counting_edits_exempt``).
    for scope in ("notes", "yoetz_owned", "scratch"):
        if scope in classes:
            return scope
    return None
