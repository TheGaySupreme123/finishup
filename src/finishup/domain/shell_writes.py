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
glob or a command substitution, a script that opens files itself, an invocation that exits without
writing (``--help``, conflicting ``-t``/``-T``), a write after the analysed head of an over-long
command. Text is not syntax: a quoted or escaped operator or keyword, a comment, a here-string, a
heredoc body, a ``$(...)`` or backtick substitution (opaque, with its own quote state), the inside
of ``[[ ... ]]`` and ``(( ... ))`` and the word ``tee`` as an argument write nothing. Control flow
is not modelled, so the bodies of compound statements (``then``, ``do``, function definitions) are
not read.

The parser is linear in its input (no backtracking pattern, no rescanning) and bounded: text longer
than ``MAX_SHELL_WRITE_CHARS`` (the hook's normalization limit) is analysed up to its last newline
inside that limit and no further, so a long ``cat > f <<'EOF'`` body still names ``f`` (also inside
the ``bash -lc '...'`` argv Codex records) while a write after the limit is not seen and the
command a cut interrupts is dropped whole. It never raises and never blocks the hook.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Final, NamedTuple, cast

from finishup.domain.command_segments import strip_wrappers, wrapped_shell_argument
from finishup.domain.write_scope import classify_write_path, scratch_path

__all__ = [
    "APPLY_PATCH_PATH",
    "MAX_SHELL_WRITE_CHARS",
    "SHELL_APPLY_PATCH",
    "bound_command",
    "codex_intercepts_shell_apply_patch",
    "command_working_directory",
    "heredoc_patch_paths",
    "patch_command_words",
    "shell_command_text",
    "shell_heredocs",
    "shell_write_paths",
    "shell_write_scope",
]

# The hook's command normalization limit (``domain.observation._MAX_OBSERVED_COMMAND_CHARS``; a
# unit test pins the two together): longer text is analysed only up to its last newline inside it.
# This bounds the work any caller can be made to do.
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
# Words after which a command, so ``((`` or ``[[``, may begin. The bodies of compound statements
# (``then cp a b``, ``f() { cp a b; }``) are not read: whether they run is control flow.
_BEFORE_COMMAND: Final = frozenset(
    {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "for"}
)
# ``$(``, ``${`` and the legacy ``$[`` open an expansion this lexer does not read into.
_EXPANSION_CLOSERS: Final = {"(": ")", "{": "}", "[": "]"}
# Stack marks of arithmetic: ``$(( ... ))`` / ``(( ... ))`` (``A``, closed by ``)``) and the legacy
# ``$[ ... ]`` (``B``, closed by ``]``). A ``<<`` inside either is a shift, never a heredoc.
_ARITHMETIC: Final = "A"
_ARITHMETIC_CLOSERS: Final = {"A": ")", "B": "]"}
_DESCRIPTOR_TARGET: Final = re.compile(r"[0-9]+-?|-", re.ASCII)
_BSD_SED_SUFFIX: Final = re.compile(r"\.[A-Za-z0-9_.~-]+", re.ASCII)

_FILE_OPERAND_SKIP: Final = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin"})
_COPY_LIKE: Final = frozenset({"cp", "mv", "install", "rsync"})
_SED_NAMES: Final = frozenset({"sed", "gsed"})
_INFORMATIONAL: Final = frozenset({"--help", "--version"})
_REMOTE_OPERAND: Final = re.compile(r"[^/]*:")
# rsync options that take a separate value (so the value is not a path) ...
_RSYNC_VALUE_OPTIONS: Final = frozenset(
    {
        "--exclude",
        "--include",
        "--exclude-from",
        "--include-from",
        "--filter",
        "--rsh",
        "--files-from",
        "--log-file",
        "--bwlimit",
        "--timeout",
        "--port",
        "--rsync-path",
        "--temp-dir",
        "--backup-dir",
        "--suffix",
        "--compare-dest",
        "--copy-dest",
        "--link-dest",
        "--chmod",
        "--chown",
        "--partial-dir",
        "--max-size",
        "--min-size",
    }
)
# ... and the ones after which it transfers nothing.
_RSYNC_NO_TRANSFER: Final = frozenset({"-n", "--dry-run", "--list-only"})
# The rollout records one more ``bash -lc`` than the hook sees, so the stream needs one level more.
_MAX_SHELL_DEPTH: Final = 4
# Wrappers (``env``, ``timeout``, ``nice`` ...) and their options come first; scanning only this
# many words keeps ``strip_wrappers`` constant-cost whatever an adversary puts in a segment.
_WRAPPER_SCAN: Final = 128


@dataclass(frozen=True, slots=True)
class _Word:
    """A shell word with its quotes and escapes removed.

    ``literal`` says no expansion could change it: it holds no unquoted ``$``, backtick, glob,
    brace or leading ``~``. A ``$`` or ``*`` that quoting or an escape made literal stays
    literal (``'/opt/$report.txt'``), so such a path is a real, attributable target. ``quoted``
    says it carries a quote or an escape (so it is not a reserved word), ``truncated`` that its
    closing quote lay beyond the input bound.
    """

    text: str
    literal: bool = True
    quoted: bool = False
    truncated: bool = False


class _Token(NamedTuple):
    kind: str  # "word" or "op"
    text: str
    literal: bool = True
    quoted: bool = False
    fd: str = ""  # op: the descriptor number written directly before it
    truncated: bool = False


class _Stop(Exception):
    """The text ends inside a construct, or the lexer cannot be sure what it means."""


def _attributable(word: _Word) -> bool:
    """A literal path: no expansion the hook cannot resolve (``$VAR``, ``~``, globs, substitution)."""

    return (
        word.literal
        and not word.truncated
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


def _expansion_closer(text: str, index: int) -> str:
    """The closer of the ``$(``, ``$((``, ``${`` or ``$[`` expansion whose ``$`` is at *index*."""

    opener = text[index + 1]
    if opener == "(" and text.startswith("(", index + 2):
        return "A"
    if opener == "[":
        return "B"
    return _EXPANSION_CLOSERS[opener]


def _heredoc_delimiter(text: str, index: int) -> tuple[tuple[str, bool, bool], int] | None:
    """``((delimiter, strips_tabs, quoted), end)`` of the heredoc whose ``<<`` ends before *index*.

    Used inside a skipped group, where a heredoc body (quotes, parentheses and all) must not decide
    where the group ends. The delimiter is taken literally, quotes removed (``'EOF'``, ``$'EOF'``).
    """

    size = len(text)
    strips = text.startswith("-", index)
    if strips:
        index += 1
    while index < size and text[index] in " \t":
        index += 1
    start = index
    parts: list[str] = []
    quoted = False
    while index < size:
        char = text[index]
        if char == "$" and text[index + 1 : index + 2] in ("'", '"'):
            index += 1  # ``$'EOF'`` and ``$"EOF"``: the quotes are the delimiter's
            quoted = True
            if text[index] == "'":
                close = text.find("'", index + 1)
                if close < 0 or "\\" in text[index + 1 : close]:
                    return None
                parts.append(text[index + 1 : close])
                index = close + 1
        elif char in "'\"":
            close = text.find(char, index + 1)
            if close < 0:
                return None
            parts.append(text[index + 1 : close])
            quoted = True
            index = close + 1
        elif char == "\\":
            if index + 1 >= size:
                return None
            parts.append(text[index + 1])
            quoted = True
            index += 2
        elif char in " \t\n;&|()<>":
            break
        else:
            parts.append(char)
            index += 1
    if index == start:
        return None
    return ("".join(parts), strips, quoted), index


def _skip_group(text: str, index: int, closer: str) -> int | None:
    """The index after the delimiter closing a ``$(``, ``${``, ``$[``, backtick or ``((`` group.

    *index* is just after the opener and *closer* its closing mark. The group is opaque to the
    lexer, but its own quotes, nested groups, comments and heredoc bodies decide where it ends, so
    ``"$(echo "x > f")"`` and ``$(cat <<EOF`` ... ``)`` are each one word. One forward pass with an
    explicit stack: linear in the group, never recursive. ``None`` when the group is not closed,
    and when it holds a ``case`` (whose patterns end in an unmatched ``)``): unsure.
    """

    stack = [closer]
    pending: list[tuple[str, bool, bool]] = []
    arithmetic = 1 if closer in _ARITHMETIC_CLOSERS else 0
    size = len(text)
    start = index
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
            elif char == "$" and following in _EXPANSION_CLOSERS:
                mark = _expansion_closer(text, index)
                arithmetic += mark in _ARITHMETIC_CLOSERS
                stack.append(mark)
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
        elif char == "$" and following in _EXPANSION_CLOSERS:
            mark = _expansion_closer(text, index)
            arithmetic += mark in _ARITHMETIC_CLOSERS
            stack.append(mark)
            index += 2
        elif char == "$" and following == "'":
            skipped = _skip_ansi_c(text, index + 2)
            if skipped is None:
                return None
            index = skipped
        elif top == ")" and char == "#" and _starts_word(text, index, start):
            newline = text.find("\n", index)  # a comment: its parentheses close nothing
            index = size if newline < 0 else newline
        elif top == ")" and text.startswith("case", index) and _starts_word(text, index, start):
            if text[index + 4 : index + 5] in (" ", "\t", "\n"):
                return None
            index += 4
        elif not arithmetic and text.startswith("<<<", index):
            index += 3
        elif not arithmetic and text.startswith("<<", index):
            parsed = _heredoc_delimiter(text, index + 2)
            if parsed is None:
                index += 2
            else:
                pending.append(parsed[0])
                index = parsed[1]
        elif char == "\n" and pending:
            index = _skip_heredocs(text, index + 1, pending)
            pending.clear()
        elif char == "(" and top in (")", "A"):
            stack.append(")")
            index += 1
        elif char == _ARITHMETIC_CLOSERS.get(top, top):
            arithmetic -= stack.pop() in _ARITHMETIC_CLOSERS
            index += 1
        else:
            index += 1
        if not stack:
            return index
    return None


def _starts_word(text: str, index: int, start: int) -> bool:
    """Whether *index* begins a shell word: after blanks, a separator or an opening parenthesis."""

    if index == start:
        return True
    before = text[index - 1]
    if before in " \t" and text[index - 2 : index - 1] == "\\":
        return False  # an escaped blank belongs to the previous word
    return before in " \t\n;&|("


def _skip_heredocs(text: str, index: int, pending: list[tuple[str, bool, bool]]) -> int:
    """The index after the bodies of the heredocs started on the line that just ended.

    A body is data to the first line equal to its delimiter (a ``<<-`` body also ignores leading
    tabs, and only tabs); an unterminated body runs to the end of the text, as in bash. In an
    unquoted heredoc a line ending in an odd number of backslashes continues on the next, and the
    joined line is what is compared (``text\\`` then ``EOF`` is ``textEOF``).
    """

    size = len(text)
    for delimiter, strip_tabs, quoted in pending:
        carry = ""  # the continued lines so far, while they could still equal the delimiter
        dead = False  # ... and once they cannot
        while index < size:
            end = text.find("\n", index)
            if end < 0:
                end = size
            physical = text[index:end]
            index = min(end + 1, size)
            if not quoted and (len(physical) - len(physical.rstrip("\\"))) % 2 == 1:
                if not dead:
                    carry += physical[:-1]
                    if len(carry.lstrip("\t")) > len(delimiter):
                        carry, dead = "", True
                continue
            line = carry + physical
            matched = not dead and (line.lstrip("\t") if strip_tabs else line) == delimiter
            carry, dead = "", False
            if matched:
                break
    return index


def _at_command(previous: _Token | None) -> bool:
    return (
        previous is None
        or (previous.kind == "op" and previous.text in _SEPARATORS)
        or (previous.kind == "word" and not previous.quoted and previous.text in _BEFORE_COMMAND)
    )


def _is_descriptor(text: str) -> bool:
    return bool(text) and text.isascii() and text.isdigit()


def _lex(text: str, *, partial: bool) -> tuple[list[_Token], bool] | None:
    """``(tokens, incomplete)`` of *text*; ``None`` if it cannot be lexed with certainty.

    A purpose-built shell lexer, because a quoted or escaped operator is text and ``shlex`` cannot
    say so: in ``echo ">" f``, ``echo \\> f`` and ``echo 'a > b'`` nothing is redirected. Words
    lose their quotes and backslashes and carry whether they are literal and quoted; an operator
    is only ever an unquoted, unescaped one; a newline ends a command and then a pending heredoc
    body is skipped as data; an unquoted ``#`` at the start of a word begins a comment; a word of
    digits directly before ``>``/``<`` is a descriptor, not an argument. ``$(...)``, ``${...}``,
    ``$'...'`` and backticks are opaque (their own quotes and nesting decide where they end), and
    the inside of ``[[ ... ]]`` and ``(( ... ))`` is not redirection.

    Text that ends inside a construct is unlexable, except with ``partial`` (a head cut by the
    input bound): the tokens before the construct are returned with ``incomplete`` set, and an
    unterminated quote becomes a ``truncated`` word.
    """

    tokens: list[_Token] = []
    buffer: list[str] = []
    pending: list[tuple[str, bool, bool]] = []
    in_word = False
    quoted = False
    literal = True
    truncated = False
    incomplete = False
    in_test = False
    delimiter_strips_tabs: bool | None = None
    index = 0
    size = len(text)

    def end_word() -> None:
        nonlocal in_word, quoted, literal, truncated, in_test, delimiter_strips_tabs
        if in_word:
            word = "".join(buffer)
            previous = tokens[-1] if tokens else None
            tokens.append(_Token("word", word, literal, quoted, "", truncated))
            if delimiter_strips_tabs is not None:
                pending.append((word, delimiter_strips_tabs, quoted))
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
        truncated = False

    try:
        while index < size:
            char = text[index]
            if char in " \t\r":
                end_word()
                index += 1
            elif char == "\n":
                end_word()
                tokens.append(_Token("op", "\n"))
                index += 1
                if pending:
                    index = _skip_heredocs(text, index, pending)
                    pending.clear()
                delimiter_strips_tabs = None
            elif char == "\\":
                if index + 1 >= size:
                    raise _Stop
                following = text[index + 1]
                if following != "\n":  # a backslash-newline joins lines
                    buffer.append(following)
                    in_word = True
                    quoted = True
                index += 2
            elif char == "'":
                close = text.find("'", index + 1)
                if close < 0:
                    if not partial:
                        raise _Stop
                    buffer.append(text[index + 1 :])
                    truncated = incomplete = True
                    close = size
                else:
                    buffer.append(text[index + 1 : close])
                in_word = True
                quoted = True
                index = close + 1
            elif char == '"':
                index += 1
                while True:
                    if index >= size:
                        if not partial:
                            raise _Stop
                        truncated = incomplete = True
                        break
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
                        if inner == "`" or following in _EXPANSION_CLOSERS:
                            end = _skip_group(
                                text,
                                index + (1 if inner == "`" else 2),
                                "`" if inner == "`" else _expansion_closer(text, index),
                            )
                            if end is None:
                                raise _Stop
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
                if delimiter_strips_tabs is not None and not in_word and following in ("'", '"'):
                    # A heredoc delimiter is taken literally; ``<<$'EOF'`` and ``<<$"EOF"`` are
                    # ``EOF``. An escape inside ``$'...'`` is not decoded: unsure, so stop.
                    if following == '"':
                        index += 1
                        continue
                    close = text.find("'", index + 2)
                    if close < 0 or "\\" in text[index + 2 : close]:
                        raise _Stop
                    buffer.append(text[index + 2 : close])
                    in_word = True
                    quoted = True
                    index = close + 1
                    continue
                literal = False
                in_word = True
                if following in _EXPANSION_CLOSERS:
                    end = _skip_group(text, index + 2, _expansion_closer(text, index))
                elif following == "'":
                    end = _skip_ansi_c(text, index + 2)
                else:
                    end = index + 1
                if end is None:
                    raise _Stop
                buffer.append(text[index:end])
                index = end
            elif char == "`":
                end = _skip_group(text, index + 1, "`")
                if end is None:
                    raise _Stop
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
                end = _skip_group(text, index + 1, _ARITHMETIC)
                if end is None:
                    raise _Stop
                tokens.append(_Token("word", "((", False))
                index = end
            elif char in _OPERATOR_CHARS and not (in_test and char in "<>()&|"):
                operator = next(
                    (item for item in _OPERATORS_LONGEST_FIRST if text.startswith(item, index)),
                    char,
                )
                descriptor = ""
                if (
                    in_word
                    and not quoted
                    and operator[0] in "<>"
                    and _is_descriptor("".join(buffer))
                ):
                    descriptor = "".join(buffer)
                    buffer.clear()
                    in_word = False  # ``2>file``: the descriptor is not an argument
                    literal = True
                end_word()
                tokens.append(_Token("op", operator, fd=descriptor))
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
    except _Stop:
        if not partial:
            return None
        # The head ends inside a construct: the word being read is not known, the tokens before it
        # are. The caller drops the command the stop interrupted.
        buffer.clear()
        in_word = False
        return tokens, True
    end_word()
    return tokens, incomplete


@dataclass(slots=True)
class _Options:
    """The options and operands of one simple command (``--`` ends the options)."""

    flags: set[str] = field(default_factory=lambda: set[str]())
    values: dict[str, _Word] = field(default_factory=lambda: dict[str, _Word]())
    counts: dict[str, int] = field(default_factory=lambda: dict[str, int]())
    operands: list[_Word] = field(default_factory=lambda: list[_Word]())
    # The word directly after a bare short option that takes only an attached value (``sed -i``):
    # on macOS it is that option's value.
    after_bare: dict[str, _Word] = field(default_factory=lambda: dict[str, _Word]())

    @property
    def informational(self) -> bool:
        """``--help`` / ``--version``: the command prints and exits, whatever else it names."""

        return not _INFORMATIONAL.isdisjoint(self.flags)


def _parse_options(
    words: list[_Word],
    *,
    short_value: str = "",
    short_optional: str = "",
    long_value: frozenset[str] = frozenset(),
) -> _Options:
    """Split *words* into options (clusters, attached and separate values) and operands.

    ``short_value`` letters take a value (the rest of the cluster, else the next word);
    ``short_optional`` letters take only an attached value and end the cluster (GNU ``sed -i.bak``,
    where the suffix swallows the letters after it); ``long_value`` long options take ``=value`` or
    the next word. Options may follow operands, as in GNU getopt.
    """

    options = _Options()
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
                options.counts[name] = options.counts.get(name, 0) + 1
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
                    elif index < size:
                        options.after_bare[key] = words[index]
                    break
                if letter in short_value:
                    options.counts[key] = options.counts.get(key, 0) + 1
                    if position < len(text):
                        options.values[key] = _Word(text[position:], word.literal)
                    elif index < size:
                        options.values[key] = words[index]
                        index += 1
                    break
    return options


def _sed_files(name: str, rest: list[_Word]) -> list[_Word]:
    """The file operands of an in-place ``sed`` (the script is not one); ``[]`` if not in place."""

    options = _parse_options(
        rest,
        short_value="efl",
        short_optional="i",
        long_value=frozenset({"--expression", "--file", "--line-length"}),
    )
    if options.informational or not {"-i", "--in-place"} & options.flags:
        return []
    script_given = bool(options.flags & {"-e", "-f", "--expression", "--file"})
    gnu = [word for word in options.operands[(0 if script_given else 1) :] if word.text != "-"]
    suffix = options.after_bare.get("-i")
    if (
        name != "sed"
        or suffix is None
        or not (suffix.text == "" or _BSD_SED_SUFFIX.fullmatch(suffix.text))
    ):
        return gnu
    # ``sed -i '' script file`` and ``sed -i .bak script file``: macOS takes the word after
    # ``-i`` as the suffix, GNU takes it as the script (or a file). Only what both readings
    # agree is a file is a write.
    operands = [word for word in options.operands if word is not suffix]
    bsd = {id(word) for word in operands[(0 if script_given else 1) :]}
    return [word for word in gnu if id(word) in bsd]


def _copy_destinations(name: str, rest: list[_Word]) -> list[tuple[_Word, bool]]:
    """``(destination, is_directory)`` of ``cp``/``mv``/``install``/``rsync``.

    ``-t DIR`` names a directory (and needs a source and no ``-T`` and one ``-t``, or the command
    fails before writing); ``install -d`` creates every operand as a directory; otherwise the last
    operand is the destination, a directory only if it ends with ``/``. A dry run writes nothing.
    """

    if name == "install":
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
    elif name == "rsync":
        options = _parse_options(rest, short_value="efBTM", long_value=_RSYNC_VALUE_OPTIONS)
        if _RSYNC_NO_TRANSFER & options.flags:
            return []
    else:
        options = _parse_options(
            rest,
            short_value="tS",
            long_value=frozenset({"--target-directory", "--suffix", "--sparse", "--no-preserve"}),
        )
    if options.informational:
        return []
    target_specs = options.counts.get("-t", 0) + options.counts.get("--target-directory", 0)
    if target_specs:
        target = options.values.get("-t") or options.values.get("--target-directory")
        if (
            target is None
            or target_specs > 1
            or options.flags & {"-T", "--no-target-directory"}
            or not options.operands
        ):
            return []  # the command fails before it writes
        return [(target, True)]
    if name == "install" and {"-d", "--directory"} & options.flags:
        return [(word, True) for word in options.operands]
    if len(options.operands) < 2:
        return []
    destination = options.operands[-1]
    if name == "rsync" and _REMOTE_OPERAND.match(destination.text):
        return []  # ``host:path`` and ``rsync://`` name a remote destination
    return [(destination, destination.text.endswith("/"))]


def bound_command(command: str) -> str:
    """*command*, or its head up to the last newline inside ``MAX_SHELL_WRITE_CHARS``.

    The bound every caller applies before it parses a hook command, so no parser can be made to do
    quadratic work on a megabyte of one token. A head with no newline is empty: no line is
    complete, so nothing is guessed.
    """

    return _bounded(command)[0]


def _bounded(command: str) -> tuple[str, bool]:
    """``(text, cut)``: *command*, or its head up to the last newline inside the bound."""

    if len(command) <= MAX_SHELL_WRITE_CHARS:
        return command, False
    head = command[:MAX_SHELL_WRITE_CHARS]
    cut = head.rfind("\n")
    return (head[:cut] if cut > 0 else ""), True


_LINE_ENDS: Final = frozenset({"\n", ";", "&&", "||", "|", "|&", "&", ";;", ")"})


def _scan(text: str, depth: int, partial: bool) -> dict[str, bool]:
    """``{path: is_directory}`` for every path *text* visibly writes, in first-seen order."""

    lexed = _lex(text, partial=partial)
    if lexed is None:
        return {}
    tokens, incomplete = lexed
    targets: dict[str, bool] = {}
    segment: list[_Word] = []
    redirects: list[_Word] = []  # what the redirections of the segment write ...
    ambiguous = False  # ... up to one that fails: bash opens them left to right, runs nothing after

    def add(path: str, directory: bool) -> None:
        targets[path] = targets.get(path, True) and directory

    def emit(word: _Word, directory: bool = False) -> None:
        if _attributable(word):
            add(word.text, directory)

    def flush(tail: bool = False) -> None:
        nonlocal ambiguous
        words = list(segment)
        written = list(redirects)
        segment.clear()
        redirects.clear()
        not_run, ambiguous = ambiguous, False
        if not tail:
            for word in written:
                emit(word)
        if not_run:
            return  # a failed redirection: the command itself is not run
        head_words = [word.text for word in words[:_WRAPPER_SCAN]]
        stripped = strip_wrappers(head_words)
        if not stripped:
            return  # nothing left to run, or too many wrappers to tell what runs
        removed = head_words[: len(head_words) - len(stripped)]
        if not _INFORMATIONAL.isdisjoint(removed):
            return  # ``timeout --help cmd`` prints and exits
        words = words[len(head_words) - len(stripped) :]
        name = os.path.basename(words[0].text)
        rest = words[1:]
        if len(words) == 3 and depth < _MAX_SHELL_DEPTH:
            inner = wrapped_shell_argument([word.text for word in words])
            if inner is not None:
                # ``bash -lc 'cat > f'``: the shell the host wrapped the command in runs the real
                # one. An argument with an expansion is expanded by the outer shell first, and
                # ``bash -n`` runs nothing: unsure.
                script = words[2]
                if "n" not in words[1].text and script.literal and (script.truncated or not tail):
                    for path, directory in _scan(inner, depth + 1, script.truncated).items():
                        add(path, directory)
                return
        if tail:
            return  # the cut interrupted this command: its operands are not all known
        if name == "tee":
            options = _parse_options(rest)
            for word in () if options.informational else options.operands:
                emit(word)
        elif name in _SED_NAMES:
            # ``sed -i 's/a/b/' f``: the first operand is the script unless ``-e``/``-f`` gave it.
            for word in _sed_files(name, rest):
                emit(word)
        elif name in _COPY_LIKE:
            for word, directory in _copy_destinations(name, rest):
                emit(word, directory)
        elif name == "touch":
            # ``-r REF`` reads REF; ``-d``/``-t`` take a time, not a file; ``-`` is stdout.
            options = _parse_options(
                rest, short_value="rdt", long_value=frozenset({"--reference", "--date", "--time"})
            )
            for word in () if options.informational else options.operands:
                if word.text != "-":
                    emit(word)
        elif name == "truncate":
            options = _parse_options(
                rest, short_value="sr", long_value=frozenset({"--size", "--reference"})
            )
            sized = {"-s", "-r", "--size", "--reference"} & options.flags
            for word in () if options.informational or not sized else options.operands:
                emit(word)
        elif name == "dd" and not any(word.text in _INFORMATIONAL for word in rest):
            outputs = [word for word in rest if word.text.startswith("of=")]
            if outputs:  # the last ``of=`` wins
                last = outputs[-1]
                emit(_Word(last.text[3:], last.literal, last.quoted))

    index = 0
    while index < len(tokens):
        token = tokens[index]
        following = tokens[index + 1] if index + 1 < len(tokens) else None
        if token.kind == "op" and token.text in _SEPARATORS:
            flush()
        elif token.kind == "op" and (
            token.text in _REDIRECT_OPERATORS
            or token.text in _OTHER_REDIRECTS
            or token.text == _DUPLICATING_REDIRECT
        ):
            if following is not None and following.kind == "word":
                target = _Word(
                    following.text, following.literal, following.quoted, following.truncated
                )
                if ambiguous:
                    pass  # opened after one that failed: never opened
                elif token.text in _REDIRECT_OPERATORS:
                    redirects.append(target)
                elif token.text == _DUPLICATING_REDIRECT:
                    if _DESCRIPTOR_TARGET.fullmatch(target.text) is not None:
                        pass  # ``>&2`` and ``>&-`` duplicate or close a descriptor
                    elif token.fd in ("", "1"):
                        redirects.append(target)  # ``>& file`` and ``1>& file`` write a file
                    else:
                        ambiguous = True  # ``2>& file`` is an ambiguous redirect
                index += 1  # the redirect's operand is never an argument of the command
            elif following is None or following.text in _LINE_ENDS:
                # A redirection with no target is a syntax error: that command is not run and
                # bash reads no further.
                segment.clear()
                redirects.clear()
                ambiguous = False
                break
        elif token.kind == "word":
            segment.append(_Word(token.text, token.literal, token.quoted, token.truncated))
        index += 1
    flush(tail=incomplete)
    return targets


def _write_targets(command: str) -> dict[str, bool]:
    text, cut = _bounded(command)
    return _scan(text, 0, cut)


def shell_write_paths(command: str) -> list[str]:
    """Every path a shell command visibly writes, absolute or relative (ADR-045).

    Reads shell tokens, never output or file content: a redirect target, a ``tee`` operand, the
    file operands of ``sed -i``, the destination of ``cp``/``mv``/``install``/``rsync`` (the last
    operand, or the ``-t`` directory), ``touch``/``truncate`` operands and ``dd of=``. A write the
    hook cannot attribute (a path built from ``$VAR`` or ``~``, a glob, a script that opens files
    itself, a command it cannot lex with certainty, a write beyond ``MAX_SHELL_WRITE_CHARS``)
    names nothing here, which only means the kernel does not count it as an edit.
    """

    return list(_write_targets(command))


def shell_write_scope(
    command: str,
    *,
    workspace: str | None,
    inside: Callable[[str], bool],
    owned_roots: tuple[str, ...] = (),
    relative_only: bool = False,
    also_written: Iterable[str] = (),
    relocated: bool = False,
    working_directory: str | None = None,
) -> str | None:
    """The ``write_scope`` a shell command earns: ``outside_workspace``, ``workspace`` or ``None``.

    Each visible write path is classified by the rules edit tools use (``domain.write_scope``):
    a real write outside the workspace wins; a write into the workspace that is not the agent's
    own notes or log, not scratch and not FinishUP-owned makes the command an edit
    (``workspace``); a command that writes only one non-counting class (notes, FinishUP material)
    or only project documentation (``docs``, n7 RC2) carries that scope, and one that writes
    nothing visible, or only scratch, claims nothing. A
    command that writes two non-counting classes (``: > NOTES.md; : > finishup_receipt.md``) counts as
    an edit, as a mixed edit-tool call does: one token cannot carry both classes' declared-output
    overrides, and a declared output of either class must keep counting. A directory destination
    (``cp -t DIR``, ``install -d DIR``, ``dest/``) is classified by where it is: the files that land
    in it are named after something else, so a notes or receipt *file name* never exempts it.
    ``relative_only`` reads only relative paths: a caller that knows no workspace root (the Codex
    rollout stream) cannot tell an absolute path inside it from one outside, so it claims only
    what a working directory makes certain. ``also_written`` adds files the caller knows the
    command writes although its tokens cannot show it (the files a shell ``apply_patch <<EOF``
    heredoc names, #1046 review); they are classified by the same rules.

    A relative target is read against the command's working directory (#1106 r2). A command that
    starts with one ``cd <literal word> &&`` and changes directory nowhere else has its relative
    targets read under that word (``cd tests && cat > golden.md`` writes ``tests/golden.md``);
    any other directory change (a later or second ``cd``, ``pushd``, ``git -C``, a ``cd`` whose
    target is not one literal word), or a working directory the caller cannot place
    (``relocated``), leaves a relative target unplaced, and an unplaced target is never project
    documentation: it counts as ``workspace``. ``working_directory`` is the absolute directory
    the command starts in when the caller knows it (the host's ``cwd``, a Codex call's
    ``workdir``); a relative ``cd`` word is read under it. ``relative_only`` never reads under a
    directory (an absolute target would be dropped); it only marks the targets unplaced.
    """

    targets = dict(_write_targets(command))
    for extra in also_written:
        if extra:
            targets.setdefault(extra, False)
    base, unplaced = command_working_directory(command)
    if relocated:
        base, unplaced = None, True
    elif working_directory is not None and not unplaced:
        start = posixpath.normpath(working_directory)
        if not start.startswith("/"):
            base, unplaced = None, True
        elif base is None:
            base = start
        elif not base.startswith("/"):
            base = posixpath.normpath(posixpath.join(start, base))
    classes: set[str] = set()
    for path, directory in targets.items():
        absolute = path.startswith("/")
        if relative_only and absolute:
            continue
        is_inside = None if workspace is None or not absolute else inside(path)
        written = posixpath.join(path, "_") if directory else path
        written_class = classify_write_path(
            written, workspace=workspace, inside=is_inside, owned_roots=owned_roots
        )
        if written_class == "docs" and not absolute and (unplaced or base is not None):
            # A relative target lands under the command's working directory. Only placed there
            # is it read as documentation: one that cannot be placed, or that is no documentation
            # where it lands (``cd tests && cat > golden.md``), may be a fixture or a golden file
            # and counts as an ordinary write. The class is otherwise read as before, so a write
            # never becomes scratch or outside the workspace by its directory alone.
            written_class = (
                "workspace"
                if base is None
                else _placed_docs_class(
                    posixpath.join(base, written),
                    workspace=workspace,
                    inside=inside,
                    owned_roots=owned_roots,
                    relative_only=relative_only,
                )
            )
        if written_class == "scratch":
            continue
        # The hook may consult its own environment (a ``TMPDIR`` outside the workspace is scratch
        # for this process); the kernel never does, so the answer is recorded as a closed token.
        if (
            written_class == "workspace"
            and absolute
            and is_inside is not True
            and scratch_path(path, workspace)
        ):
            continue
        classes.add(written_class)
    if "outside_workspace" in classes:
        return "outside_workspace"
    if "workspace" in classes or len(classes) > 1:
        return "workspace"
    # Only the agent's notes, FinishUP's own material or project documentation: the same closed
    # token an edit tool carries, so a declared output of that kind keeps counting
    # (``non_counting_edits_exempt``, ``stale_exempt_write_tokens``).
    # Frozen legacy identifier (ADR-048): ``yoetz_owned`` is the recorded write-scope token.
    for scope in ("notes", "yoetz_owned", "docs"):
        if scope in classes:
            return scope
    return None


# A directory change anywhere in a command: ``cd``/``pushd``/``popd`` as a command word, or a
# ``git -C <dir>``. Searched over the whole text (a heredoc body that says ``cd`` only makes the
# reader more careful).
_DIRECTORY_CHANGE: Final = re.compile(
    r"(?:^|[\s;&|(`])(?:cd|pushd|popd)(?=$|[\s;&|)])"
    r"|(?:^|[\s;&|(])git(?:[ \t]+-c[ \t]+[^\s;&|()]+)*[ \t]+-C(?=[\s=]|$)",
    re.MULTILINE,
)
# One leading ``cd <word> &&``: the word is a literal path (no expansion, quoting or option).
_LEADING_CD: Final = re.compile(r"\A[ \t]*cd[ \t]+([A-Za-z0-9_./+@%:,=-]+)[ \t]*&&")


def command_working_directory(command: str) -> tuple[str | None, bool]:
    """Where a shell command's relative writes land, as ``(directory, unplaced)`` (#1106 r2).

    ``(None, False)``: the command changes no directory, so its relative targets are read against
    the caller's working directory. ``(word, False)``: it starts with one ``cd <word> &&`` (a
    literal word, not ``-``, never starting with ``~``) and changes directory nowhere else.
    ``(None, True)``: any other directory change, so a relative target cannot be placed.
    """

    head = _LEADING_CD.match(command)
    rest = command[head.end() :] if head is not None else command
    if _DIRECTORY_CHANGE.search(rest) is not None:
        return None, True
    if head is None:
        return None, False
    word = head.group(1)
    if word.startswith(("-", "~")):
        return None, True
    return posixpath.normpath(word), False


def shell_command_text(value: object) -> str | None:
    """The shell text a command value runs, for the write readers (#1106 r2).

    A string is itself. A native argv is its script when it is one host-shell layer
    (``["/bin/bash", "-lc", SCRIPT]``, the shape a Codex ``CommandExecution`` item or a legacy
    ``shell`` call records), so a long heredoc patch is read from the script itself rather than
    from a joined copy the token parsers cut at ``MAX_SHELL_WRITE_CHARS``; any other argv is
    its ``shlex.join``. Anything else is ``None``.
    """

    if type(value) is str:
        return value
    if isinstance(value, (list, tuple)) and value:
        words = cast(Sequence[object], value)
        if all(type(word) is str for word in words):
            argv = [cast(str, word) for word in words]
            script = wrapped_shell_argument(argv)
            return script if script is not None else shlex.join(argv)
    return None


def _placed_docs_class(
    path: str,
    *,
    workspace: str | None,
    inside: Callable[[str], bool],
    owned_roots: tuple[str, ...],
    relative_only: bool,
) -> str:
    """``docs`` when a relative documentation target is still documentation where it lands."""

    absolute = path.startswith("/")
    is_inside = None if relative_only or workspace is None or not absolute else inside(path)
    landed = classify_write_path(
        path,
        workspace=None if relative_only else workspace,
        inside=is_inside,
        owned_roots=owned_roots,
    )
    return "docs" if landed == "docs" else "workspace"


# A heredoc that feeds a patch tool writes the files the patch names, which no shell token shows.
_HEREDOC_START: Final = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
# A heredoc fed to ``apply_patch``: the line before ``<<`` ends in the command name.
SHELL_APPLY_PATCH: Final = re.compile(r"(?:^|[\s;&|(])(?:apply_patch|applypatch)\s*$")
APPLY_PATCH_PATH: Final = re.compile(
    r"^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$", re.MULTILINE
)
_MAX_SHELL_HEREDOCS: Final = 8
# Codex 0.159 intercepts a shell ``apply_patch`` only as the whole script: ``apply_patch <<EOF``
# or ``cd <one word> && apply_patch <<EOF`` (``codex-rs/apply-patch/src/invocation.rs``).
_INTERCEPTED_APPLY_PATCH: Final = re.compile(
    r"\A\s*(?:cd[ \t]+(?:'[^'\n]*'|\"[^\"\n]*\"|[^\s'\"\;&|()<>$`-][^\s'\"\;&|()<>$`]*)"
    r"[ \t]*&&[ \t]*)?(?:apply_patch|applypatch)[ \t]*\Z"
)
# The separators before the last simple command of the text before ``<<`` (the one the heredoc
# feeds). A split, never a search anchored at ``$``: that backtracks quadratically over a long
# blank run between two separators (#1106 r1).
_PREFIX_SEPARATOR: Final = re.compile(r"&&|\|\||[;|&(]")
# A ``git apply``/``patch`` invocation is a few words; a longer one is not read.
_MAX_PATCH_COMMAND_CHARS: Final = 4_096
# Unified-diff file headers; a path is the text up to a tab (a timestamp may follow).
_DIFF_NEW_PATH: Final = re.compile(r"\+\+\+ ([^\t\n]+)")
_DIFF_OLD_PATH: Final = re.compile(r"--- ([^\t\n]+)")
# ``git apply`` options that leave the working tree alone ...
_GIT_APPLY_NO_WORKTREE: Final = frozenset(
    {"--check", "--stat", "--numstat", "--summary", "--cached", "--build-fake-ancestor"}
)
# ... and the ones that take no separate value and do not move what it writes.
_GIT_APPLY_FLAGS: Final = frozenset(
    {
        "-",
        "-3",
        "--3way",
        "--apply",
        "--index",
        "-R",
        "--reverse",
        "--reject",
        "-v",
        "--verbose",
        "-q",
        "--quiet",
        "--recount",
        "--unidiff-zero",
        "--allow-empty",
        "--inaccurate-eof",
        "--ignore-whitespace",
        "--ignore-space-change",
    }
)
# ``patch`` options that change nothing on disk ...
_PATCH_NO_WRITE: Final = frozenset({"--dry-run", "-C", "--check"})
# ... and the same no-value, path-neutral set for it.
_PATCH_FLAGS: Final = frozenset(
    {
        "-N",
        "--forward",
        "-R",
        "--reverse",
        "-f",
        "--force",
        "-t",
        "--batch",
        "-s",
        "--silent",
        "--quiet",
        "-u",
        "--unified",
        "-l",
        "--ignore-whitespace",
        "-E",
        "--remove-empty-files",
        "-b",
        "--backup",
        "--no-backup-if-mismatch",
        "--verbose",
    }
)
_VALUE_FLAG: Final = re.compile(r"^(?:--whitespace=\S+|-C[0-9]+|-F[0-9]+|--fuzz=[0-9]+)$")
_STRIP_FLAG: Final = re.compile(r"^(?:-p|--strip=)([0-9]{1,2})$", re.ASCII)
# ``patch`` without ``-p``: strip only one leading ``a/``/``b/`` component (the class needs only
# the location and the name).
_STRIP_DIFF_PREFIX: Final = -1


class _Heredoc(NamedTuple):
    prefix: str
    suffix: str
    body: str
    start: int  # the index of the ``<<`` line
    end: int  # the index of the closing delimiter line


def _heredocs(command: str) -> list[_Heredoc]:
    lines = command.split("\n")
    found: list[_Heredoc] = []
    index = 0
    while index < len(lines) and len(found) < _MAX_SHELL_HEREDOCS:
        line = lines[index]
        start = index
        match = _HEREDOC_START.search(line)
        index += 1
        if match is None:
            continue
        delimiter = match.group(2)
        body: list[str] = []
        while index < len(lines) and lines[index].strip() != delimiter:
            body.append(lines[index])
            index += 1
        if index >= len(lines):
            break  # unterminated heredoc: not a complete edit
        found.append(
            _Heredoc(
                line[: match.start()], line[match.end() :], "\n".join(body) + "\n", start, index
            )
        )
        index += 1
    return found


def shell_heredocs(command: str) -> list[tuple[str, str, str]]:
    """Return bounded ``(prefix, suffix, body)`` triples for each complete heredoc in a command."""

    return [(heredoc.prefix, heredoc.suffix, heredoc.body) for heredoc in _heredocs(command)]


def codex_intercepts_shell_apply_patch(command: str) -> bool:
    """Whether Codex applies this shell ``apply_patch <<EOF`` itself instead of running it.

    Codex 0.159 intercepts only a script that is that one statement, ``apply_patch <<'EOF' ...
    EOF`` or ``cd <path> && apply_patch <<'EOF' ... EOF``, and fires no post-tool event for it
    (#1041). A script with anything before or after it (the patch, then ``pytest -q``) runs in the
    shell through Codex's ``apply_patch`` alias, and its post-tool event arrives as usual.
    """

    if "<<" not in command:
        return False
    found = _heredocs(command)
    if len(found) != 1:
        return False
    heredoc = found[0]
    lines = command.split("\n")
    head = "\n".join([*lines[: heredoc.start], heredoc.prefix])
    tail = "\n".join([heredoc.suffix, *lines[heredoc.end + 1 :]])
    return _INTERCEPTED_APPLY_PATCH.match(head) is not None and not tail.strip()


def heredoc_patch_paths(command: str) -> tuple[str, ...]:
    """The files a heredoc-fed patch in a shell command names (n7 RC2, #1046 review).

    The command's own tokens show no write for these, so the patch headers are the write. Three
    forms, each only from a complete heredoc: ``apply_patch``/``applypatch`` (its ``*** Add|
    Update|Delete File:`` and ``*** Move to:`` headers), and ``git apply`` and ``patch`` (each
    unified-diff ``+++`` header, or its ``---`` when ``+++`` is ``/dev/null``, less the leading
    components the ``-p`` strip removes: ``git apply`` defaults to one, a bare ``patch`` drops one
    leading ``a/``/``b/``). An invocation that writes nothing (``git apply --check``/``--cached``,
    ``patch --dry-run``), reads its patch from a file (an operand, ``-i``), moves what it writes
    (``-d``, ``-o``, ``--directory``) or uses an option this reader does not know names nothing,
    as does a header it cannot place (a quoted path). A whole command ``bash -lc '...'`` (a joined
    native argv) is read through that one shell layer.

    Every step is linear in the text (a hook payload is at most 1 MiB). Unlike the token parsers,
    the heredoc reader is not cut at ``MAX_SHELL_WRITE_CHARS``: a patch longer than that is still
    a write, and missing it would leave an earlier verification current.
    """

    if "<<" not in command:
        return ()
    paths = _heredoc_patch_paths(command)
    if paths:
        return paths
    # A native argv joined into one string (``/bin/bash -lc 'git apply <<EOF ...'``, the shape a
    # Codex ``CommandExecution`` item or a legacy ``shell`` call records): the heredoc sits inside
    # the quoted script, so read that script once, as ``shell_write_scope`` does.
    script = _wrapped_script(command)
    return _heredoc_patch_paths(script) if script is not None else ()


def _wrapped_script(command: str) -> str | None:
    """``X`` for a whole command ``bash -lc X`` / ``sh -c X`` in any quoting, else ``None``.

    Read only within ``MAX_SHELL_WRITE_CHARS``: a caller holding the native argv passes its script
    instead (``shell_command_text``), so a longer joined copy is never re-split here.
    """

    try:
        words = shlex.split(bound_command(command), posix=True)
    except ValueError:
        return None
    return wrapped_shell_argument(words)


def _heredoc_patch_paths(command: str) -> tuple[str, ...]:
    paths: list[str] = []
    for heredoc in _heredocs(command):
        if SHELL_APPLY_PATCH.search(heredoc.prefix):
            paths.extend(match.strip() for match in APPLY_PATCH_PATH.findall(heredoc.body))
            continue
        strip = _diff_patch_strip(heredoc.prefix)
        if strip is not None:
            paths.extend(_diff_paths(heredoc.body, strip))
    return tuple(path for path in paths if path)


def _diff_patch_strip(prefix: str) -> int | None:
    """The ``-p`` strip of a ``git apply``/``patch`` a heredoc feeds; ``None`` when it names no write."""

    last = _PREFIX_SEPARATOR.split(prefix)[-1]
    if ")" in last or len(last) > _MAX_PATCH_COMMAND_CHARS:
        return None
    try:
        words = patch_command_words(shlex.split(last, posix=True))
    except ValueError:
        return None
    if not words:
        return None
    name = words[0].rsplit("/", 1)[-1]
    if name == "git" and words[1:2] == ["apply"]:
        flags, no_write, known, strip = words[2:], _GIT_APPLY_NO_WORKTREE, _GIT_APPLY_FLAGS, 1
    elif name in {"patch", "gpatch"}:
        flags, no_write, known, strip = words[1:], _PATCH_NO_WRITE, _PATCH_FLAGS, None
    else:
        return None
    index = 0
    while index < len(flags):
        flag = flags[index]
        index += 1
        if flag in no_write:
            return None
        strip_match = _STRIP_FLAG.match(flag)
        if strip_match is not None:
            strip = int(strip_match.group(1))
        elif flag == "-p" and index < len(flags) and flags[index].isdecimal():
            strip = int(flags[index][:2])
            index += 1
        elif flag not in known and _VALUE_FLAG.match(flag) is None:
            return None
    return _STRIP_DIFF_PREFIX if strip is None else strip


# ``sudo`` options that take no value, and the ones that take one (``-u root``).
_SUDO_FLAGS: Final = frozenset({"-n", "-E", "-H", "-S", "-k", "-b", "-P", "--non-interactive"})
_SUDO_VALUE_FLAGS: Final = frozenset({"-u", "-g", "--user", "--group"})
# ``git`` global options before the subcommand: ``-C <dir>`` and ``-c <name>=<value>``.
_GIT_GLOBAL_VALUE_FLAGS: Final = frozenset({"-C", "-c"})


def patch_command_words(words: Sequence[str]) -> list[str]:
    """*words* of one simple command as a patch reader reads them (#1106 r2).

    The wrappers ``strip_wrappers`` drops, then a leading ``sudo`` with its options (it changes
    who writes, never what), and ``git``'s ``-C <dir>``/``-c <name>=<value>`` before its
    subcommand, so ``sudo patch -p1`` and ``git -C . apply`` read as the patch tools they run.
    The directory ``-C`` names is a directory change (``command_working_directory``), so the
    files it writes are never read as documentation. Anything else is returned as it is.
    """

    rest = strip_wrappers(words)
    if rest and rest[0].rsplit("/", 1)[-1] == "sudo":
        rest.pop(0)
        while rest and rest[0].startswith("-"):
            option = rest.pop(0)
            if option == "--":
                break
            if option in _SUDO_VALUE_FLAGS:
                if not rest:
                    return []
                rest.pop(0)
            elif option not in _SUDO_FLAGS:
                return []
        rest = strip_wrappers(rest)
    if rest and rest[0].rsplit("/", 1)[-1] == "git":
        index = 1
        while index < len(rest) and rest[index] in _GIT_GLOBAL_VALUE_FLAGS:
            index += 2
        if index > len(rest):
            return []
        rest = [rest[0], *rest[index:]]
    return rest


def _diff_paths(body: str, strip: int) -> list[str]:
    # A file header is a ``---`` line directly followed by a ``+++`` line: pairing them line by
    # line keeps a removed ``-- comment`` or an added ``++ x`` body line from posing as one.
    lines = body.split("\n")
    paths: list[str] = []
    for old_line, new_line in zip(lines, lines[1:], strict=False):
        old = _DIFF_OLD_PATH.match(old_line)
        new = _DIFF_NEW_PATH.match(new_line)
        if old is None or new is None:
            continue
        header = new.group(1).strip()
        if header == "/dev/null":
            header = old.group(1).strip()  # a deletion names its old path
        if not header or header == "/dev/null" or header.startswith('"'):
            continue
        path = _strip_components(header, strip)
        if path:
            paths.append(path)
    return paths


def _strip_components(path: str, strip: int) -> str | None:
    if strip == _STRIP_DIFF_PREFIX:
        head, _, rest = path.partition("/")
        return rest if head in {"a", "b"} and rest else path
    parts = path.split("/")
    if strip >= len(parts):
        return None  # ``patch`` skips a header with fewer components than its strip
    return "/".join(parts[strip:]) or None
