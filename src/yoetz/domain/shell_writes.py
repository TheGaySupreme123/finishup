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
of ``[[ ... ]]`` and ``(( ... ))`` and the word ``tee`` as an argument write nothing.

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
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final, NamedTuple

from yoetz.domain.command_segments import strip_wrappers, wrapped_shell_argument
from yoetz.domain.write_scope import classify_write_path, scratch_path

__all__ = ["MAX_SHELL_WRITE_CHARS", "shell_write_paths", "shell_write_scope"]

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
# Reserved words that begin a command inside a compound statement (``then cp a b``); only an
# unquoted, unescaped one is syntax (``'then' cp a b`` runs a command named ``then``).
_RESERVED_PREFIX: Final = frozenset(
    {"if", "then", "else", "elif", "do", "while", "until", "!", "{"}
)
# Words after which ``((`` still begins an arithmetic command.
_BEFORE_COMMAND: Final = _RESERVED_PREFIX | {"for"}
# ``$(``, ``${`` and the legacy ``$[`` open an expansion this lexer does not read into.
_EXPANSION_CLOSERS: Final = {"(": ")", "{": "}", "[": "]"}
_DESCRIPTOR_TARGET: Final = re.compile(r"[0-9]+-?|-", re.ASCII)
_BSD_SED_SUFFIX: Final = re.compile(r"\.[A-Za-z0-9_.~-]+", re.ASCII)

_FILE_OPERAND_SKIP: Final = frozenset(
    {"-", "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin"}
)
_COPY_LIKE: Final = frozenset({"cp", "mv", "install", "rsync"})
_SED_NAMES: Final = frozenset({"sed", "gsed"})
_INFORMATIONAL: Final = frozenset({"--help", "--version"})
_REMOTE_OPERAND: Final = re.compile(r"[^/]*:")
_MAX_SHELL_DEPTH: Final = 3
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


def _heredoc_delimiter(text: str, index: int) -> tuple[tuple[str, bool], int] | None:
    """``((delimiter, strips_tabs), end)`` of the heredoc whose operator ends just before *index*.

    Used inside a skipped group, where a heredoc body (quotes, parentheses and all) must not decide
    where the group ends. ``None`` when the word is not plainly a delimiter (``1<<2``).
    """

    size = len(text)
    strips = text.startswith("-", index)
    if strips:
        index += 1
    while index < size and text[index] in " \t":
        index += 1
    start = index
    parts: list[str] = []
    while index < size:
        char = text[index]
        if char in "'\"":
            close = text.find(char, index + 1)
            if close < 0:
                return None
            parts.append(text[index + 1 : close])
            index = close + 1
        elif char == "\\":
            if index + 1 >= size:
                return None
            parts.append(text[index + 1])
            index += 2
        elif char in " \t\n;&|()<>":
            break
        else:
            parts.append(char)
            index += 1
    if index == start or not (text[start] in "'\"\\_" or text[start].isalpha()):
        return None
    return ("".join(parts), strips), index


def _skip_group(text: str, index: int, closer: str) -> int | None:
    """The index after the delimiter closing a ``$(``, ``${``, ``$[``, backtick or ``((`` group.

    *index* is just after the opener and *closer* its closing character. The group is opaque to
    the lexer, but its own quotes, nested groups, comments and heredoc bodies decide where it ends,
    so ``"$(echo "x > f")"`` and ``$(cat <<EOF`` ... ``)`` are each one word. One forward pass with
    an explicit stack: linear in the group, never recursive. ``None`` when the group is not closed.
    """

    stack = [closer]
    pending: list[tuple[str, bool]] = []
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
                stack.append(_EXPANSION_CLOSERS[following])
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
            stack.append(_EXPANSION_CLOSERS[following])
            index += 2
        elif char == "$" and following == "'":
            skipped = _skip_ansi_c(text, index + 2)
            if skipped is None:
                return None
            index = skipped
        elif char == "#" and (index == start or text[index - 1] in " \t\n;&|("):
            newline = text.find("\n", index)  # a comment: its parentheses close nothing
            index = size if newline < 0 else newline
        elif text.startswith("<<<", index):
            index += 3
        elif text.startswith("<<", index):
            parsed = _heredoc_delimiter(text, index + 2)
            if parsed is None:
                index += 2
            else:
                pending.append(parsed[0])
                index = parsed[1]
        elif char == "\n" and pending:
            index = _skip_heredocs(text, index + 1, pending)
            pending.clear()
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
    pending: list[tuple[str, bool]] = []
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
                                "`" if inner == "`" else _EXPANSION_CLOSERS[following],
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
                    end = _skip_group(text, index + 2, _EXPANSION_CLOSERS[following])
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
                end = _skip_group(text, index + 1, ")")
                if end is None:
                    raise _Stop
                tokens.append(_Token("word", "((", False))
                index = end
            elif char in _OPERATOR_CHARS and not (in_test and char in "<>"):
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


def _sed_files(rest: list[_Word]) -> list[_Word]:
    """The file operands of an in-place ``sed`` (the script is not one); ``[]`` if not in place."""

    options = _parse_options(
        rest,
        short_value="efl",
        short_optional="i",
        long_value=frozenset({"--expression", "--file", "--line-length"}),
    )
    if options.informational or not {"-i", "--in-place"} & options.flags:
        return []
    operands = options.operands
    if options.flags & {"-e", "-f", "--expression", "--file"}:
        return operands  # the script was given by an option
    if len(operands) >= 3 and (
        operands[0].text == "" or _BSD_SED_SUFFIX.fullmatch(operands[0].text)
    ):
        # macOS: ``sed -i '' script file`` and ``sed -i .bak script file`` give the suffix as a
        # separate word. GNU sed never has an empty or dotted script followed by two operands.
        operands = operands[1:]
    return operands[1:]


def _copy_destinations(name: str, rest: list[_Word]) -> list[tuple[_Word, bool]]:
    """``(destination, is_directory)`` of ``cp``/``mv``/``install``/``rsync``.

    ``-t DIR`` names a directory (and needs a source and no ``-T`` and one ``-t``, or the command
    fails before writing); ``install -d`` creates every operand as a directory; otherwise the last
    operand is the destination, a directory only if it ends with ``/``.
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
        options = _parse_options(rest)
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


def _bounded(command: str) -> tuple[str, bool]:
    """``(text, cut)``: *command*, or its head up to the last newline inside the bound.

    A head with no newline is empty: no line is complete, so nothing is guessed.
    """

    if len(command) <= MAX_SHELL_WRITE_CHARS:
        return command, False
    head = command[:MAX_SHELL_WRITE_CHARS]
    cut = head.rfind("\n")
    return (head[:cut] if cut > 0 else ""), True


def _scan(text: str, depth: int, partial: bool) -> dict[str, bool]:
    """``{path: is_directory}`` for every path *text* visibly writes, in first-seen order."""

    lexed = _lex(text, partial=partial)
    if lexed is None:
        return {}
    tokens, incomplete = lexed
    targets: dict[str, bool] = {}
    segment: list[_Word] = []

    def add(path: str, directory: bool) -> None:
        targets[path] = targets.get(path, True) and directory

    def emit(word: _Word, directory: bool = False) -> None:
        if _attributable(word):
            add(word.text, directory)

    def flush(tail: bool = False) -> None:
        words = list(segment)
        segment.clear()
        start = 0
        while (
            start < len(words) and not words[start].quoted and words[start].text in _RESERVED_PREFIX
        ):
            start += 1
        words = words[start:]
        head_words = [word.text for word in words[:_WRAPPER_SCAN]]
        stripped = strip_wrappers(head_words)
        if not stripped:
            return  # nothing left to run, or too many wrappers to tell what runs
        words = words[len(head_words) - len(stripped) :]
        name = os.path.basename(words[0].text)
        rest = words[1:]
        if len(words) == 3 and depth < _MAX_SHELL_DEPTH:
            inner = wrapped_shell_argument([word.text for word in words])
            if inner is not None:
                # ``bash -lc 'cat > f'``: the shell the host wrapped the command in runs the real
                # one. An argument with an expansion is expanded by the outer shell first: unsure.
                script = words[2]
                if script.literal and (script.truncated or not tail):
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
            for word in _sed_files(rest):
                emit(word)
        elif name in _COPY_LIKE:
            for word, directory in _copy_destinations(name, rest):
                emit(word, directory)
        elif name == "touch":
            # ``-r REF`` reads REF; ``-d``/``-t`` take a time, not a file.
            options = _parse_options(
                rest, short_value="rdt", long_value=frozenset({"--reference", "--date", "--time"})
            )
            for word in () if options.informational else options.operands:
                emit(word)
        elif name == "truncate":
            options = _parse_options(
                rest, short_value="sr", long_value=frozenset({"--size", "--reference"})
            )
            for word in () if options.informational else options.operands:
                emit(word)
        elif name == "dd" and not any(word.text in _INFORMATIONAL for word in rest):
            for word in rest:
                if word.text.startswith("of="):
                    emit(_Word(word.text[3:], word.literal, word.quoted))

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
                if token.text in _REDIRECT_OPERATORS:
                    emit(target)
                elif (
                    token.text == _DUPLICATING_REDIRECT
                    and token.fd in ("", "1")
                    and _DESCRIPTOR_TARGET.fullmatch(target.text) is None
                ):
                    # ``>& file`` and ``1>& file`` send the output to a file; ``>&2``/``>&-``
                    # duplicate or close a descriptor, and ``2>& file`` is an ambiguous redirect.
                    emit(target)
                index += 1  # the redirect's operand is never an argument of the command
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
) -> str | None:
    """The ``write_scope`` a shell command earns: ``outside_workspace``, ``workspace`` or ``None``.

    Each visible write path is classified by the rules edit tools use (``domain.write_scope``):
    a real write outside the workspace wins; a write into the workspace that is not the agent's
    own notes or log, not scratch and not Yoetz-owned makes the command an edit
    (``workspace``); a command that writes only one non-counting class (notes, Yoetz material)
    carries that scope, and one that writes nothing visible, or only scratch, claims nothing. A
    command that writes two non-counting classes (``: > NOTES.md; : > yoetz_receipt.md``) counts as
    an edit, as a mixed edit-tool call does: one token cannot carry both classes' declared-output
    overrides, and a declared output of either class must keep counting. A directory destination
    (``cp -t DIR``, ``install -d DIR``, ``dest/``) is classified by where it is: the files that land
    in it are named after something else, so a notes or receipt *file name* never exempts it.
    ``relative_only`` reads only relative paths: a caller that knows no workspace root (the Codex
    rollout stream) cannot tell an absolute path inside it from one outside, so it claims only
    what a working directory makes certain.
    """

    classes: set[str] = set()
    for path, directory in _write_targets(command).items():
        absolute = path.startswith("/")
        if relative_only and absolute:
            continue
        is_inside = None if workspace is None or not absolute else inside(path)
        written = posixpath.join(path, "_") if directory else path
        written_class = classify_write_path(
            written, workspace=workspace, inside=is_inside, owned_roots=owned_roots
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
    # Only the agent's notes or Yoetz's own material: the same closed token an edit tool carries,
    # so a declared output of that kind keeps counting (``non_counting_edits_exempt``).
    for scope in ("notes", "yoetz_owned"):
        if scope in classes:
            return scope
    return None
