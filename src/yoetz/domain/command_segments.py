"""Bounded, quote-aware segments of one shell command for planned-verification matching.

A planned verification (an obligation's requested ``command`` item) is matched against the hook's
installation-keyed command commitments (#909, #977). The whole-command commitment alone missed
every run an agent wrapped or composed: ``cd /app && python evaluate.py && git diff --check``,
``bash run.sh > log 2>&1``, ``time python run.py``, ``FOO=1 make test``, ``npm test | tail``, or a
``bash <<'EOF'`` script whose lines include the planned command. This module splits such a
command into the simple commands it runs, so the hook can commit to each one beside the whole
command and the kernel can match a planned command to any of them.

Splitting is deliberately conservative and deterministic:

* top-level (unquoted, outside ``$(...)`` and backticks) ``&&``, ``||``, ``;``, ``|``, ``&``,
  subshell parentheses and line breaks separate segments; ``#`` comments are dropped;
* each segment drops leading ``VAR=value`` assignments, ``time`` (``-p``), ``env`` with its
  assignments and options, ``nohup``, ``exec``, the shell keywords that introduce a command
  (``if``, ``then``, ``do``, ``else``, ``elif``, ``while``, ``until``, ``{``, ``!``) and every
  redirection word (``> f``, ``>> f``, ``2>&1``, ``&> f``, ``< f``, ``<<'EOF'``);
* the body of a here-document fed to a shell (``bash <<'EOF'``, ``sh -s <<EOF``) is split the same
  way; any other here-document (``python3 - <<'PY'``, ``cat > f <<EOF``) is data, not commands;
* a segment that is itself a shell wrapper (``bash -lc '...'``, ``sh -c "..."``) also contributes
  the segments of its argument.

An unterminated quote, substitution or here-document makes the command unsplittable: only the
whole-command identity then exists, exactly as before. The result exists only to be committed by
the caller; segment text is never stored, displayed, logged or sent.

The composition says what the whole command's outcome means for one of its segments: ``single``
(one simple command with prefixes or redirections: its outcome is the segment's), ``and_chain``
(``&&`` only: a success means every segment succeeded, a failure names no segment) and ``masked``
(any other composition, where the whole outcome says nothing about one segment).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Final

from yoetz.domain.observation import normalize_observed_command, observed_command_commitment

__all__ = [
    "COMMAND_COMPOSITIONS",
    "MAX_SEGMENT_COMMITMENTS",
    "CommandSegments",
    "command_segment_commitments",
    "command_segments",
    "requested_command_shape",
]

# At most this many segment commitments travel with one observed command: the first and last
# half of the distinct segments in command order, so a script's final verification line survives.
MAX_SEGMENT_COMMITMENTS: Final = 32
COMMAND_COMPOSITIONS: Final = frozenset({"single", "and_chain", "masked"})
_MAX_DEPTH: Final = 3
_MAX_TEXT_CHARS: Final = 16_384
_SHELLS: Final = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_SHELL_COMMAND_FLAG_RE: Final = re.compile(r"^-[a-z]*c[a-z]*$", re.ASCII)
_ASSIGNMENT_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=", re.ASCII)
_REDIRECTION_RE: Final = re.compile(r"^(?:[0-9]+|&)?(>>|>\||>&|>|<<<|<<-|<<|<&|<>|<)(.*)$", re.S)
_LEADING_KEYWORDS: Final = frozenset(
    {"if", "then", "do", "else", "elif", "while", "until", "{", "!", "nohup", "exec"}
)
_CLOSING_WORDS: Final = frozenset({"}", "fi", "done", "esac", "then", "do", "else"})
# A template placeholder: ``<`` not glued to a preceding word or digit (``a<b``, ``2<x`` are
# redirections or comparisons), a name, further words that start with a letter, and a ``>``
# followed by end of text, whitespace or a quote (``<in.txt>out.txt`` is two redirections).
_PLACEHOLDER_RE: Final = re.compile(
    r"(?<![A-Za-z0-9_])<[A-Za-z][A-Za-z0-9_.:-]*(?: [A-Za-z][A-Za-z0-9_.:-]*)*>(?=$|[\s'\"])",
    re.ASCII,
)
_PROSE_WORD_RE: Final = re.compile(r"^[A-Za-z]+[,.:;]?$", re.ASCII)
_MASKING_SEPARATORS: Final = frozenset({"||", ";", "|", "&", "\n", "(", ")"})


@dataclass(frozen=True, slots=True)
class CommandSegments:
    """The distinct simple commands of one normalized command, in first-seen order."""

    segments: tuple[str, ...]
    composition: str


@dataclass(slots=True)
class _Split:
    segments: list[str]
    bodies: dict[int, list[str]]
    separators: set[str]


def _split_top_level(text: str) -> _Split | None:
    """Split at top-level separators; return ``None`` on any unterminated construct."""

    segments: list[str] = []
    bodies: dict[int, list[str]] = {}
    separators: set[str] = set()
    current: list[str] = []
    pending: list[tuple[str, bool, int]] = []
    quote: str | None = None
    substitution = 0
    backtick = False
    index = 0
    length = len(text)

    def flush() -> None:
        segment = "".join(current).strip()
        current.clear()
        if segment:
            segments.append(segment)

    while index < length:
        char = text[index]
        if quote == "'":
            current.append(char)
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "\\" and index + 1 < length:
            if quote is None and substitution == 0 and not backtick and text[index + 1] == "\n":
                current.append(" ")
            else:
                current.append(text[index : index + 2])
            index += 2
            continue
        if quote == '"':
            current.append(char)
            if char == '"':
                quote = None
            index += 1
            continue
        if char in "'\"":
            quote = char
            current.append(char)
            index += 1
            continue
        if char == "`":
            backtick = not backtick
            current.append(char)
            index += 1
            continue
        if char == "$" and index + 1 < length and text[index + 1] == "(":
            substitution += 1
            current.append("$(")
            index += 2
            continue
        if substitution > 0:
            if char == "(":
                substitution += 1
            elif char == ")":
                substitution -= 1
            current.append(char)
            index += 1
            continue
        if backtick:
            current.append(char)
            index += 1
            continue
        if char == "#" and (not current or current[-1][-1:] in {" ", "\t", "\n"}):
            while index < length and text[index] != "\n":
                index += 1
            continue
        if char == "<" and text.startswith("<<", index) and not text.startswith("<<<", index):
            start = index
            index += 2
            strip_tabs = index < length and text[index] == "-"
            if strip_tabs:
                index += 1
            while index < length and text[index] in " \t":
                index += 1
            delimiter_start = index
            if index < length and text[index] in "'\"":
                closing = text.find(text[index], index + 1)
                if closing < 0:
                    return None
                delimiter = text[index + 1 : closing]
                index = closing + 1
            else:
                while index < length and text[index] not in " \t\n;&|<>()":
                    index += 1
                delimiter = text[delimiter_start:index].replace("\\", "")
            if not delimiter:
                return None
            current.append(text[start:index])
            # The segment the operator appears in owns the body: the next index to be appended.
            pending.append((delimiter, strip_tabs, len(segments)))
            continue
        if char == "\n":
            flush()
            separators.add("\n")
            index += 1
            for delimiter, strip_tabs, owner in pending:
                body: list[str] = []
                while True:
                    if index >= length:
                        return None
                    end = text.find("\n", index)
                    line = text[index:] if end < 0 else text[index:end]
                    index = length if end < 0 else end + 1
                    if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                        break
                    body.append(line)
                bodies.setdefault(owner, []).append("\n".join(body))
            pending.clear()
            continue
        two = text[index : index + 2]
        if two in {"&&", "||", ";;", "|&"}:
            flush()
            separators.add({"&&": "&&", "||": "||", ";;": ";", "|&": "|"}[two])
            index += 2
            continue
        if char in ";|()":
            flush()
            separators.add(char)
            index += 1
            continue
        if char == "&":
            previous = current[-1][-1:] if current else ""
            following = text[index + 1 : index + 2]
            if previous in {">", "<"} or following == ">":
                current.append(char)
            else:
                flush()
                separators.add("&")
            index += 1
            continue
        current.append(char)
        index += 1
    if quote is not None or substitution or backtick or pending:
        return None
    flush()
    return _Split(segments, bodies, separators)


def _words(segment: str) -> list[str] | None:
    """Split one segment into raw word spans (quotes kept), or ``None`` when unbalanced."""

    words: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in segment:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if quote is None and char in " \t\n":
            if current:
                words.append("".join(current))
                current.clear()
            continue
        current.append(char)
        if char == "\\" and quote != "'":
            escaped = True
        elif quote is None and char in "'\"":
            quote = char
        elif char == quote:
            quote = None
    if quote is not None:
        return None
    if current:
        words.append("".join(current))
    return words


@dataclass(frozen=True, slots=True)
class _Cleaned:
    text: str | None
    negated: bool
    shell_reads_stdin: bool


def _clean_segment(segment: str) -> _Cleaned:
    words = _words(segment)
    if words is None:
        return _Cleaned(" ".join(segment.split()) or None, False, False)
    negated = False
    kept: list[str] = []
    skip_next = False
    leading = True
    after_time = False
    in_env = False
    for word in words:
        if skip_next:
            skip_next = False
            continue
        redirection = _REDIRECTION_RE.match(word)
        if redirection is not None:
            if not redirection.group(2):
                skip_next = True
            continue
        if leading:
            if word == "!":
                negated = True
                continue
            if word in _LEADING_KEYWORDS:
                continue
            if word == "time":
                after_time = True
                continue
            if after_time and word == "-p":
                continue
            if word == "env":
                in_env = True
                continue
            if in_env and (word.startswith("-") or _ASSIGNMENT_RE.match(word)):
                continue
            if _ASSIGNMENT_RE.match(word):
                continue
            leading = False
        kept.append(word)
    while kept and kept[-1] in _CLOSING_WORDS and len(kept) > 1:
        kept.pop()
    if len(kept) == 1 and kept[0] in _CLOSING_WORDS:
        kept = []
    shell_reads_stdin = bool(kept) and (
        kept[0].replace("\\", "/").rsplit("/", 1)[-1] in _SHELLS
        and all(
            word.startswith("-") and _SHELL_COMMAND_FLAG_RE.match(word) is None for word in kept[1:]
        )
    )
    return _Cleaned(" ".join(kept) or None, negated, shell_reads_stdin)


def _wrapped_argument(text: str) -> str | None:
    """``X`` for a segment ``bash -lc X`` / ``sh -c X`` in any quoting, else ``None``."""

    try:
        words = shlex.split(text, posix=True)
    except ValueError:
        return None
    if len(words) != 3:
        return None
    shell = words[0].replace("\\", "/").rsplit("/", 1)[-1]
    if shell not in _SHELLS or _SHELL_COMMAND_FLAG_RE.fullmatch(words[1]) is None:
        return None
    return words[2]


def _collect(text: str, depth: int, out: list[str]) -> tuple[bool, bool, bool]:
    """Append ``text``'s segments to ``out``; return ``(splittable, masked, chained)``."""

    split = _split_top_level(text)
    if split is None:
        return False, False, False
    masked = bool(split.separators & _MASKING_SEPARATORS)
    chained = len(split.segments) > 1
    for position, segment in enumerate(split.segments):
        cleaned = _clean_segment(segment)
        masked = masked or cleaned.negated
        if cleaned.text is not None:
            normalized = normalize_observed_command(cleaned.text) or cleaned.text
            out.append(normalized)
            inner = _wrapped_argument(cleaned.text)
            if inner is None and normalized != cleaned.text:
                inner = normalized
            if inner is not None and depth < _MAX_DEPTH:
                ok, inner_masked, inner_chained = _collect(inner, depth + 1, out)
                masked = masked or (ok and inner_masked)
                chained = chained or (ok and inner_chained)
        for body in split.bodies.get(position, ()):
            if cleaned.shell_reads_stdin and depth < _MAX_DEPTH:
                # A script fed to a shell: its lines are commands, and the whole outcome is the
                # script's, which says nothing about one line.
                masked = True
                _collect(body, depth + 1, out)
    return True, masked, chained


def command_segments(normalized: str) -> CommandSegments | None:
    """The simple commands of one normalized command, or ``None`` when there is nothing new.

    ``normalized`` is ``normalize_observed_command``'s output. ``None`` means the command is
    unsplittable or is already a single simple command (its whole identity is its only one).
    """

    if type(normalized) is not str or not normalized or len(normalized) > _MAX_TEXT_CHARS:
        return None
    collected: list[str] = []
    splittable, masked, chained = _collect(normalized, 0, collected)
    if not splittable:
        return None
    distinct = tuple(dict.fromkeys(item for item in collected if item and "\x00" not in item))
    if not distinct or distinct == (normalized,):
        return None
    composition = "masked" if masked else "and_chain" if chained else "single"
    return CommandSegments(distinct, composition)


def command_segment_commitments(
    key_material: bytes, normalized: str
) -> tuple[tuple[str, ...], str] | None:
    """Sorted keyed commitments to ``normalized``'s segments, and its composition, or ``None``.

    The whole-command commitment is never repeated here. Beyond ``MAX_SEGMENT_COMMITMENTS``
    distinct segments only the first and last halves in command order are committed.
    """

    segments = command_segments(normalized)
    if segments is None:
        return None
    whole = observed_command_commitment(key_material, normalized)
    commitments = [
        value
        for value in dict.fromkeys(
            observed_command_commitment(key_material, segment) for segment in segments.segments
        )
        if value != whole
    ]
    if not commitments:
        return None
    if len(commitments) > MAX_SEGMENT_COMMITMENTS:
        half = MAX_SEGMENT_COMMITMENTS // 2
        commitments = commitments[:half] + commitments[-half:]
    return tuple(sorted(commitments)), segments.composition


def _unquoted(value: str) -> str:
    """``value`` with every quoted span blanked out, so only shell-visible text is inspected."""

    output: list[str] = []
    quote: str | None = None
    escaped = False
    for char in value:
        if escaped:
            escaped = False
            output.append(" ")
            continue
        if char == "\\" and quote != "'":
            escaped = True
            output.append(" ")
            continue
        if quote is None and char in "'\"":
            quote = char
            output.append(" ")
            continue
        if char == quote:
            quote = None
            output.append(" ")
            continue
        output.append(" " if quote is not None else char)
    return "".join(output)


def requested_command_shape(value: str) -> str:
    """Classify a requested ``command`` item: ``command``, ``placeholder`` or ``prose``.

    ``placeholder``: an unquoted ``<name>`` token (``<ciphertext_file>``, ``<output-dir>``) a
    template left for the agent to fill; no shell would run it as written. ``prose``: three or
    more plain words led by a capitalized one (``Broad GSEA CLI``), with no path, flag, option,
    assignment or other shell syntax; such a description names no command a hook could observe.
    Anything else, including every single token (``legacy-score``), is a ``command``.
    """

    if type(value) is not str:
        return "command"
    if _PLACEHOLDER_RE.search(_unquoted(value)) is not None:
        return "placeholder"
    words = value.split()
    if (
        len(words) >= 3
        # Title case with at least two letters (``Broad``), so ``R CMD check pkg`` stays a command.
        and len(words[0]) >= 2
        and words[0][:1].isupper()
        and words[0][1:2].islower()
        and all(_PROSE_WORD_RE.fullmatch(word) is not None for word in words)
    ):
        return "prose"
    return "command"
