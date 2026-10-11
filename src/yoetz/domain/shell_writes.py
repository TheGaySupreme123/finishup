"""What a shell command visibly writes, and the write scope that earns it (ADR-045, tb4n3 RC-5).

``edited_after_last_verification`` and the stale-verification facts used to see only edit-tool
calls, so ``cat > solve.py <<'EOF'``, ``sed -i`` and ``cp build/out.json out.json`` changed the
work invisibly. A hook (or the Codex rollout stream) reads the command's shell tokens, never its
output or any file, and names the paths it visibly writes: a redirect target (``>``, ``>>``,
``>|``, ``&>``, ``>& file``, ``<>``), a ``tee`` operand, the file operands of ``sed -i``, the
destination of ``cp``/``mv``/``install``/``rsync`` (the last operand, or ``-t DIR``; every operand
of ``install -d``), ``touch``/``truncate`` operands and ``dd of=``. Each path is classified by the
same rules as an edit tool's (``domain.write_scope``), so the answer is one rule everywhere.
Closed tokens only; no path or command text leaves this module.

The two errors are not equal. A false write tells the agent its verification is stale; a missed
write hides an edit made after it. When the parser cannot be sure, it names **no** write rather than
a guessed one: unbalanced quotes, an unterminated expansion, a path built from ``$VAR``, ``~``, a
glob or a command substitution, a script that opens files itself, a write after the analysed head
of an over-long command. Text is not syntax: a quoted or escaped operator, a comment, a here-string,
a heredoc body, a ``$(...)`` or backtick substitution (opaque, with its own quote state), the
inside of ``[[ ... ]]`` and ``(( ... ))`` and the word ``tee`` as an argument write nothing.

The parser is linear in its input (no backtracking pattern, no rescanning) and bounded: a command
longer than ``MAX_SHELL_WRITE_CHARS`` (the hook's normalization limit) is analysed up to its last
complete line inside that limit and no further, so a long ``cat > f <<'EOF'`` body still names ``f``
while a write after the limit is not seen. It never raises and never blocks the hook.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, NamedTuple

from yoetz.domain.command_segments import strip_wrappers, wrapped_shell_argument
from yoetz.domain.write_scope import classify_write_path, scratch_path

__all__ = ["MAX_SHELL_WRITE_CHARS", "shell_write_paths", "shell_write_scope"]

# The hook's command normalization limit (``domain.observation._MAX_OBSERVED_COMMAND_CHARS``; a
# unit test pins the two together): a longer command is analysed only up to its last complete line
# inside it. This bounds the work any caller can be made to do.
MAX_SHELL_WRITE_CHARS: Final = 16_384

# Operators that write their next word (a redirect target); ``<>`` opens read-write and creates an
# absent file ...
_REDIRECT_OPERATORS: Final = frozenset({">", ">>", ">|", "&>", "&>>", "<>"})
# ... ``>&`` writes a file unless its target is a descriptor (``>&2``, ``>&-``) ...
_DUPLICATING_REDIRECT: Final = ">&"
# ... the redirects that only read or duplicate (their next word is a source, a descriptor or a
# heredoc delimiter, never a write) ...
_OTHER_REDIRECTS: Final = frozenset({"<", "<<", "<<<", "<<-", "<&"})
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
# Reserved words that begin a command inside a compound statement (``then cp a b``).
_RESERVED_PREFIX: Final = frozenset(
    {"if", "then", "else", "elif", "do", "while", "until", "!", "{"}
)
# Words after which ``((`` still begins an arithmetic command.
_BEFORE_COMMAND: Final = _RESERVED_PREFIX | {"for"}
_DESCRIPTOR_TARGET: Final = re.compile(r"[0-9]+-?|-", re.ASCII)

_FILE_OPERAND_SKIP: Final = frozenset(
    {"-", "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin"}
)
_COPY_LIKE: Final = frozenset({"cp", "mv", "install", "rsync"})
_SED_NAMES: Final = frozenset({"sed", "gsed"})
_REMOTE_OPERAND: Final = re.compile(r"[^/]*:")
_MAX_SHELL_DEPTH: Final = 3


@dataclass(frozen=True, slots=True)
class _Word:
    """A shell word with its quotes and escapes removed.

    ``literal`` says no expansion could change it: it holds no unquoted ``$``, backtick, glob,
    brace or leading ``~``. A ``$`` or ``*`` that quoting or an escape made literal stays
    literal (``'/opt/$report.txt'``), so such a path is a real, attributable target.
    """

    text: str
    literal: bool


class _Token(NamedTuple):
    kind: str  # "word" or "op"
    text: str
    flag: bool  # word: literal; op: a file-descriptor number directly precedes it


def _attributable(word: _Word) -> bool:
    """A literal path: no expansion the hook cannot resolve (``$VAR``, ``~``, globs, substitution)."""

    return (
        word.literal
        and bool(word.text)
        and word.text not in _FILE_OPERAND_SKIP
        and not any(char in word.text for char in "\x00\r\n")
    )


def _skip_ansi_c(text: str, index: int) -> int | None:
    """The index after the closing quote of a ``$'...'`` string whose body starts at *index*."""

    size = len(text)
    while index < size:
        char = text[index]
        if char == "\\":
            index += 2
        elif char == "'":
            return index + 1
        else:
            index += 1
    return None


def _skip_group(text: str, index: int, closer: str) -> int | None:
    """The index after the delimiter closing a ``$(``, ``${``, backtick or ``((`` group.

    *index* is just after the opener and *closer* its closing character (``)``, ``}`` or a
    backtick). The group is opaque to the lexer, but its own quotes and nested groups decide where
    it ends, so ``"$(echo "x > f")"`` is one word. One forward pass with an explicit stack: linear
    in the group, never recursive. ``None`` when the group is not closed.
    """

    stack = [closer]
    size = len(text)
    while index < size:
        char = text[index]
        top = stack[-1]
        following = text[index + 1] if index + 1 < size else ""
        if char == "\\":
            index += 2
        elif top == "`":
            if char == "`":
                stack.pop()
            index += 1
        elif top == '"':
            if char == '"':
                stack.pop()
                index += 1
            elif char == "$" and following in ("(", "{"):
                stack.append(")" if following == "(" else "}")
                index += 2
            elif char == "`":
                stack.append("`")
                index += 1
            else:
                index += 1
        elif char == "'":
            close = text.find("'", index + 1)
            if close < 0:
                return None
            index = close + 1
        elif char == '"' or char == "`":
            stack.append(char)
            index += 1
        elif char == "$" and following in ("(", "{"):
            stack.append(")" if following == "(" else "}")
            index += 2
        elif char == "$" and following == "'":
            skipped = _skip_ansi_c(text, index + 2)
            if skipped is None:
                return None
            index = skipped
        elif char == "(" and top == ")":
            stack.append(")")
            index += 1
        elif char == top:
            stack.pop()
            index += 1
        else:
            index += 1
        if not stack:
            return index
    return None


def _skip_heredocs(text: str, index: int, pending: list[tuple[str, bool]]) -> int:
    """The index after the bodies of the heredocs started on the line that just ended.

    A body is data to the first line equal to its delimiter (a ``<<-`` body also ignores leading
    tabs, and only tabs); an unterminated body runs to the end of the text, as in bash.
    """

    size = len(text)
    for delimiter, strip_tabs in pending:
        while index < size:
            end = text.find("\n", index)
            if end < 0:
                end = size
            line = text[index:end]
            index = min(end + 1, size)
            if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                break
    return index


def _at_command(previous: _Token | None) -> bool:
    return (
        previous is None
        or (previous.kind == "op" and previous.text in _SEPARATORS)
        or (previous.kind == "word" and previous.text in _BEFORE_COMMAND)
    )


def _lex(text: str) -> list[_Token] | None:
    """Tokens of *text* (``word`` or ``op``); ``None`` if it cannot be lexed with certainty.

    A purpose-built shell lexer, because a quoted or escaped operator is text and ``shlex`` cannot
    say so: in ``echo ">" f``, ``echo \\> f`` and ``echo 'a > b'`` nothing is redirected. Words
    lose their quotes and backslashes and carry whether they are literal; an operator is only ever
    an unquoted, unescaped one; a newline ends a command and then a pending heredoc body is
    skipped as data; an unquoted ``#`` at the start of a word begins a comment; a word of digits
    directly before ``>``/``<`` is a descriptor, not an argument. ``$(...)``, ``${...}``,
    ``$'...'`` and backticks are opaque (their own quotes and nesting decide where they end), and
    the inside of ``[[ ... ]]`` and ``(( ... ))`` is not redirection.
    """

    tokens: list[_Token] = []
    buffer: list[str] = []
    pending: list[tuple[str, bool]] = []
    in_word = False
    quoted = False
    literal = True
    in_test = False
    delimiter_strips_tabs: bool | None = None
    index = 0
    size = len(text)

    def end_word() -> None:
        nonlocal in_word, quoted, literal, in_test, delimiter_strips_tabs
        if in_word:
            word = "".join(buffer)
            previous = tokens[-1] if tokens else None
            tokens.append(_Token("word", word, literal))
            if delimiter_strips_tabs is not None:
                pending.append((word, delimiter_strips_tabs))
                delimiter_strips_tabs = None
            if not quoted:
                if word == "[[" and _at_command(previous):
                    in_test = True
                elif word == "]]":
                    in_test = False
        buffer.clear()
        in_word = False
        quoted = False
        literal = True

    while index < size:
        char = text[index]
        if char in " \t\r":
            end_word()
            index += 1
        elif char == "\n":
            end_word()
            tokens.append(_Token("op", "\n", False))
            index += 1
            if pending:
                index = _skip_heredocs(text, index, pending)
                pending.clear()
            delimiter_strips_tabs = None
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
                following = text[index + 1] if index + 1 < size else ""
                if inner == '"':
                    index += 1
                    break
                if inner == "\\" and following != "" and following in '"\\$`\n':
                    if following != "\n":
                        buffer.append(following)
                    index += 2
                elif inner == "$" or inner == "`":
                    literal = False
                    if inner == "`" or following in ("(", "{"):
                        end = _skip_group(
                            text,
                            index + (1 if inner == "`" else 2),
                            "`" if inner == "`" else (")" if following == "(" else "}"),
                        )
                        if end is None:
                            return None
                        buffer.append(text[index:end])
                        index = end
                    else:
                        buffer.append("$")
                        index += 1
                else:
                    buffer.append(inner)
                    index += 1
            in_word = True
            quoted = True
        elif char == "$":
            following = text[index + 1] if index + 1 < size else ""
            literal = False
            in_word = True
            if following in ("(", "{"):
                end = _skip_group(text, index + 2, ")" if following == "(" else "}")
            elif following == "'":
                end = _skip_ansi_c(text, index + 2)
            else:
                end = index + 1
            if end is None:
                return None
            buffer.append(text[index:end])
            index = end
        elif char == "`":
            end = _skip_group(text, index + 1, "`")
            if end is None:
                return None
            buffer.append(text[index:end])
            literal = False
            in_word = True
            index = end
        elif char == "#" and not in_word:
            while index < size and text[index] != "\n":
                index += 1
        elif (
            char == "("
            and not in_word
            and text.startswith("((", index)
            and _at_command(tokens[-1] if tokens else None)
        ):
            # An arithmetic command, ``(( i > 5 ))`` or ``for ((i = n; i > 0; i--))``: opaque.
            end = _skip_group(text, index + 1, ")")
            if end is None:
                return None
            tokens.append(_Token("word", "((", False))
            index = end
        elif char in _OPERATOR_CHARS and not (in_test and char in "<>"):
            operator = next(
                (item for item in _OPERATORS_LONGEST_FIRST if text.startswith(item, index)), char
            )
            descriptor = False
            if in_word and not quoted and operator[0] in "<>" and _is_descriptor("".join(buffer)):
                buffer.clear()
                in_word = False  # ``2>file``: the descriptor is not an argument
                literal = True
                descriptor = True
            end_word()
            tokens.append(_Token("op", operator, descriptor))
            delimiter_strips_tabs = (operator == "<<-") if operator in ("<<", "<<-") else None
            index += len(operator)
        else:
            if char in "*?[]{}":
                literal = False
            elif char == "~" and (not in_word or (buffer and buffer[-1][-1:] in ("=", ":"))):
                literal = False
            buffer.append(char)
            in_word = True
            index += 1
    end_word()
    return tokens


def _is_descriptor(text: str) -> bool:
    return bool(text) and text.isascii() and text.isdigit()


@dataclass(slots=True)
class _Options:
    """The options and operands of one simple command (``--`` ends the options)."""

    flags: set[str]
    values: dict[str, _Word]
    operands: list[_Word]


def _parse_options(
    words: list[_Word],
    *,
    short_value: str = "",
    short_optional: str = "",
    long_value: frozenset[str] = frozenset(),
    bsd_empty_suffix: bool = False,
) -> _Options:
    """Split *words* into options (clusters, attached and separate values) and operands.

    ``short_value`` letters take a value (the rest of the cluster, else the next word);
    ``short_optional`` letters take only an attached value and end the cluster (GNU ``sed -i.bak``,
    where the suffix swallows the letters after it); ``long_value`` long options take ``=value`` or
    the next word. With ``bsd_empty_suffix`` a bare ``-i`` followed by an empty word consumes it
    (macOS ``sed -i '' script file``). Options may follow operands, as in GNU getopt.
    """

    options = _Options(set(), {}, [])
    index = 0
    size = len(words)
    options_ended = False
    while index < size:
        word = words[index]
        text = word.text
        index += 1
        if options_ended or not text.startswith("-") or text == "-":
            options.operands.append(word)
        elif text == "--":
            options_ended = True
        elif text.startswith("--"):
            name, equals, value = text.partition("=")
            options.flags.add(name)
            if name in long_value:
                if equals:
                    options.values[name] = _Word(value, word.literal)
                elif index < size:
                    options.values[name] = words[index]
                    index += 1
        else:
            position = 1
            while position < len(text):
                letter = text[position]
                key = "-" + letter
                options.flags.add(key)
                position += 1
                if letter in short_optional:
                    if position < len(text):
                        options.values[key] = _Word(text[position:], word.literal)
                    elif bsd_empty_suffix and index < size and words[index].text == "":
                        index += 1
                    break
                if letter in short_value:
                    if position < len(text):
                        options.values[key] = _Word(text[position:], word.literal)
                    elif index < size:
                        options.values[key] = words[index]
                        index += 1
                    break
    return options


def _sed_files(rest: list[_Word]) -> list[_Word]:
    """The file operands of an in-place ``sed`` (the script is not one); ``[]`` if not in place."""

    options = _parse_options(
        rest,
        short_value="efl",
        short_optional="i",
        long_value=frozenset({"--expression", "--file", "--line-length"}),
        bsd_empty_suffix=True,
    )
    if "-i" not in options.flags and "--in-place" not in options.flags:
        return []
    script_given = bool(options.flags & {"-e", "-f", "--expression", "--file"})
    return options.operands if script_given else options.operands[1:]


def _copy_destinations(head: str, rest: list[_Word]) -> list[_Word]:
    """The destination of ``cp``/``mv``/``install``/``rsync``: ``-t DIR``, else the last operand."""

    if head == "install":
        options = _parse_options(
            rest,
            short_value="mogSt",
            long_value=frozenset(
                {
                    "--mode",
                    "--owner",
                    "--group",
                    "--suffix",
                    "--target-directory",
                    "--strip-program",
                }
            ),
        )
    elif head == "rsync":
        options = _parse_options(rest)
    else:
        options = _parse_options(
            rest,
            short_value="tS",
            long_value=frozenset({"--target-directory", "--suffix", "--sparse", "--no-preserve"}),
        )
    target = options.values.get("-t") or options.values.get("--target-directory")
    if target is not None:
        return [target]
    if head == "install" and ("-d" in options.flags or "--directory" in options.flags):
        return options.operands  # every operand is a directory to create
    if len(options.operands) < 2:
        return []
    destination = options.operands[-1]
    if head == "rsync" and _REMOTE_OPERAND.match(destination.text):
        return []  # ``host:path`` and ``rsync://`` name a remote destination
    return [destination]


def _bounded(command: str) -> str:
    """*command*, or its head up to the last complete line inside ``MAX_SHELL_WRITE_CHARS``."""

    if len(command) <= MAX_SHELL_WRITE_CHARS:
        return command
    head = command[:MAX_SHELL_WRITE_CHARS]
    cut = head.rfind("\n")
    while cut > 0 and head[cut - 1] == "\\":  # a line continued past the limit is not complete
        cut = head.rfind("\n", 0, cut)
    return head[:cut] if cut > 0 else ""


def shell_write_paths(command: str, _depth: int = 0) -> list[str]:
    """Every path a shell command visibly writes, absolute or relative (ADR-045).

    Reads shell tokens, never output or file content: a redirect target, a ``tee`` operand, the
    file operands of ``sed -i``, the destination of ``cp``/``mv``/``install``/``rsync`` (the last
    operand, or ``-t DIR``), ``touch``/``truncate`` operands and ``dd of=``. A write the hook
    cannot attribute (a path built from ``$VAR`` or ``~``, a glob, a script that opens files
    itself, a command it cannot lex with certainty, a write beyond ``MAX_SHELL_WRITE_CHARS``)
    names nothing here, which only means the kernel does not count it as an edit.
    """

    tokens = _lex(_bounded(command))
    if tokens is None:
        return []
    paths: dict[str, None] = {}
    segment: list[_Word] = []

    def emit(word: _Word) -> None:
        if _attributable(word):
            paths.setdefault(word.text)

    def flush() -> None:
        words = list(segment)
        segment.clear()
        start = 0
        while start < len(words) and words[start].text in _RESERVED_PREFIX:
            start += 1
        words = words[start:]
        stripped = strip_wrappers([word.text for word in words])
        words = words[len(words) - len(stripped) :]
        if not words:
            return
        head = os.path.basename(words[0].text)
        rest = words[1:]
        inner = (
            wrapped_shell_argument([word.text for word in words])
            if _depth < _MAX_SHELL_DEPTH
            else None
        )
        if inner is not None:
            # ``bash -lc 'cat > f'``: the shell the host wrapped the command in runs the real one.
            for path in shell_write_paths(inner, _depth + 1):
                paths.setdefault(path)
        elif head == "tee":
            for word in _parse_options(rest).operands:
                emit(word)
        elif head in _SED_NAMES:
            # ``sed -i 's/a/b/' f``: the first operand is the script unless ``-e``/``-f`` gave it.
            for word in _sed_files(rest):
                emit(word)
        elif head in _COPY_LIKE:
            for word in _copy_destinations(head, rest):
                emit(word)
        elif head == "touch":
            # ``-r REF`` reads REF; ``-d``/``-t`` take a time, not a file.
            for word in _parse_options(
                rest, short_value="rdt", long_value=frozenset({"--reference", "--date", "--time"})
            ).operands:
                emit(word)
        elif head == "truncate":
            for word in _parse_options(
                rest, short_value="sr", long_value=frozenset({"--size", "--reference"})
            ).operands:
                emit(word)
        elif head == "dd":
            for word in rest:
                if word.text.startswith("of="):
                    emit(_Word(word.text[3:], word.literal))

    index = 0
    while index < len(tokens):
        kind, text, flag = tokens[index]
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if kind == "op" and text in _SEPARATORS:
            flush()
        elif kind == "op" and (
            text in _REDIRECT_OPERATORS or text in _OTHER_REDIRECTS or text == _DUPLICATING_REDIRECT
        ):
            if following is not None and following[0] == "word":
                target = _Word(following[1], following[2])
                if text in _REDIRECT_OPERATORS:
                    emit(target)
                elif (
                    text == _DUPLICATING_REDIRECT
                    and not flag
                    and _DESCRIPTOR_TARGET.fullmatch(target.text) is None
                ):
                    # ``>& file`` sends both streams to a file; ``>&2``/``>&-`` duplicate or close
                    # a descriptor, and ``2>& file`` is an ambiguous redirect in bash.
                    emit(target)
                index += 1  # the redirect's operand is never an argument of the command
        elif kind == "word":
            segment.append(_Word(text, flag))
        index += 1
    flush()
    return list(paths)


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
    (``workspace``); a command that writes only one non-counting class (notes, Yoetz material)
    carries that scope, and one that writes nothing visible claims nothing. A command that writes
    two non-counting classes (``: > NOTES.md; : > yoetz_receipt.md``) counts as an edit, as a
    mixed edit-tool call does: one token cannot carry both classes' declared-output overrides, and
    a declared output of either class must keep counting. ``relative_only`` reads only relative
    paths: a caller that knows no workspace root (the Codex rollout stream) cannot tell an
    absolute path inside it from one outside, so it claims only what a working directory makes
    certain.
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
    if "workspace" in classes or len(classes) > 1:
        return "workspace"
    # Only the agent's notes, Yoetz's own material or scratch: the same closed token an edit tool
    # carries, so a declared output of that kind keeps counting (``non_counting_edits_exempt``).
    for scope in ("notes", "yoetz_owned", "scratch"):
        if scope in classes:
            return scope
    return None
