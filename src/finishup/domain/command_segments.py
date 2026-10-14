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

**Canonical commitments (ADR-045, tb4n3 RC-5).** A planned verification used to match only when
its text equalled the run's text, the run's whole command, or one of the run's segments. Real
agents wrap and reshape what they run: ``timeout 3000 python3 /app/x.py``, ``env FOO=1 pytest``,
``/usr/bin/g++ ...`` with the source files appended to a task-quoted flag set, ``python -m pytest``
for ``pytest``. ``canonical_words`` reduces one simple command to its canonical argv (wrappers
``timeout``/``nice``/``ionice``/``nohup``/``stdbuf``/``env``/``setsid`` and ``VAR=`` assignments
dropped, ``uv run``-style launchers dropped, argv[0] reduced to its basename, ``python3`` and
``pythonX.Y`` to ``python``, ``python -m pytest`` to ``pytest``). From it ``canonical_commitments``
derives three kinds of domain-separated keyed commitments, committed beside the segment
commitments (never confusable with them): ``full`` (the whole canonical argv: a clean,
normalized match), ``prefix`` (each leading run of at least two tokens: the run kept going after
the planned command) and ``flag`` (one per argument after argv[0]: the planned program and its
flags are all present, in any order). The planned side computes the same kinds from its own text,
so a match carries *which* kind matched; ``full`` is clean, ``prefix`` and ``flag`` count as a run
but are disclosed as such (``planned_verification_matched_by_prefix``), never as clean
verification. A single-token planned command only ever matches whole.

The composition says what the whole command's outcome means for one of its segments: ``single``
(one simple command with prefixes or redirections: its outcome is the segment's), ``and_chain``
(``&&`` only: a success means every segment succeeded, a failure names no segment) and ``masked``
(any other composition, where the whole outcome says nothing about one segment).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from finishup.domain.observation import normalize_observed_command, observed_command_commitment

__all__ = [
    "CANONICAL_KINDS",
    "COMMAND_COMPOSITIONS",
    "MAX_CANONICAL_COMMITMENTS",
    "MAX_COMMAND_COMMITMENTS",
    "MAX_SEGMENT_COMMITMENTS",
    "CommandSegments",
    "CommandStructure",
    "PlannedSegment",
    "SimpleCommand",
    "canonical_command_commitments",
    "canonical_commitment",
    "canonical_words",
    "command_segment_commitments",
    "command_segments",
    "exact_segment_commitments",
    "command_structure",
    "planned_segments",
    "requested_command_shape",
    "strip_wrappers",
    "wrapped_shell_argument",
]

# At most this many segment commitments travel with one observed command: the first and last
# half of the distinct segments in command order, so a script's final verification line survives.
MAX_SEGMENT_COMMITMENTS: Final = 32
# Canonical commitments (ADR-045) travel beside them, in their own bounded budget; the observed
# command carries at most ``MAX_COMMAND_COMMITMENTS`` in all (the action ``command`` text has a
# fixed byte bound, and every commitment is 76 bytes).
MAX_CANONICAL_COMMITMENTS: Final = 48
MAX_COMMAND_COMMITMENTS: Final = MAX_SEGMENT_COMMITMENTS + MAX_CANONICAL_COMMITMENTS
# The longest leading run of arguments committed as a prefix, and the most arguments committed
# as flags, per simple command.
_MAX_PREFIX_TOKENS: Final = 10
_MAX_FLAG_TOKENS: Final = 24
_MAX_TOKEN_CHARS: Final = 512
CANONICAL_KINDS: Final = ("full", "prefix", "flag")
_CANONICAL_DOMAIN: Final = b"yoetz/command-canonical/v1/"
COMMAND_COMPOSITIONS: Final = frozenset({"single", "and_chain", "masked"})
_MAX_DEPTH: Final = 3
_MAX_TEXT_CHARS: Final = 16_384
_SHELLS: Final = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_SHELL_COMMAND_FLAG_RE: Final = re.compile(r"^-[a-z]*c[a-z]*$", re.ASCII)
_ASSIGNMENT_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=", re.ASCII)
_AMBIGUOUS_WORD_RE: Final = re.compile(r"[\s'\"\\]")
# ``env`` options that take a separate operand (``env -u NAME cmd``, ``env -C DIR cmd``).
_ENV_OPTIONS_WITH_OPERAND: Final = frozenset(
    {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}
)
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
    # The segment sends its output into a file (``> f``, ``>> f``, ``>| f``), not ``/dev/null``
    # and not a file-descriptor duplication (``2>&1``).
    writes: bool = False


_OUTPUT_FILE_OPERATORS: Final = frozenset({">", ">>", ">|"})


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
    skip_env_operand = False
    writes = False
    pending_target = False
    for word in words:
        if skip_next:
            skip_next = False
            if pending_target:
                pending_target = False
                writes = writes or not (word == "/dev/null" or word.startswith("&"))
            continue
        redirection = _REDIRECTION_RE.match(word)
        if redirection is not None:
            if redirection.group(1) in _OUTPUT_FILE_OPERATORS:
                target = redirection.group(2)
                if target:
                    writes = writes or not (target == "/dev/null" or target.startswith("&"))
                else:
                    pending_target = True
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
            if in_env and word in _ENV_OPTIONS_WITH_OPERAND:
                skip_env_operand = True
                continue
            if in_env and skip_env_operand:
                skip_env_operand = False
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
    return _Cleaned(" ".join(kept) or None, negated, shell_reads_stdin, writes)


def wrapped_shell_argument(words: Sequence[str]) -> str | None:
    """``X`` for the words of ``bash -lc X`` / ``sh -c X`` (any shell path), else ``None``."""

    if len(words) != 3:
        return None
    shell = words[0].replace("\\", "/").rsplit("/", 1)[-1]
    if shell not in _SHELLS or _SHELL_COMMAND_FLAG_RE.fullmatch(words[1]) is None:
        return None
    return words[2]


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


@dataclass(frozen=True, slots=True)
class SimpleCommand:
    """One simple command of a composed command: its normalized text and canonical argv.

    ``words`` is ``canonical_words`` of the segment (wrappers and assignments dropped, argv[0]
    reduced to its basename, ``python3`` to ``python``), ``text`` the normalized segment text
    exactly as ``command_segments`` lists it, and ``writes`` whether the segment sends its output
    into a file. Exists only to be committed or classified; never stored, displayed or sent.
    """

    text: str
    words: tuple[str, ...]
    writes: bool = False


@dataclass(frozen=True, slots=True)
class CommandStructure:
    """The simple commands of one normalized command, in command order, and how they compose.

    ``commands`` holds every distinct simple command (a shell wrapper's argument and a shell
    heredoc's lines contribute theirs; the wrapper itself does not). ``composition`` is
    ``single``, ``and_chain`` or ``masked`` as for ``CommandSegments``; ``compound`` is true when
    the command is more than one simple command or uses any shell composition.
    """

    commands: tuple[SimpleCommand, ...]
    composition: str
    compound: bool


def _collect(
    text: str,
    depth: int,
    out: list[str],
    commands: list[SimpleCommand] | None = None,
) -> tuple[bool, bool, bool]:
    """Append ``text``'s segments to ``out``; return ``(splittable, masked, chained)``.

    ``commands`` (when given) receives each simple command, not the shell wrappers around them.
    """

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
            if commands is not None and inner is None:
                commands.append(
                    SimpleCommand(
                        normalized, canonical_words(_split_words(normalized)), cleaned.writes
                    )
                )
            if inner is not None and depth < _MAX_DEPTH:
                ok, inner_masked, inner_chained = _collect(inner, depth + 1, out, commands)
                masked = masked or (ok and inner_masked)
                chained = chained or (ok and inner_chained)
        for body in split.bodies.get(position, ()):
            if cleaned.shell_reads_stdin and depth < _MAX_DEPTH:
                # A script fed to a shell: its lines are commands, and the whole outcome is the
                # script's, which says nothing about one line.
                masked = True
                _collect(body, depth + 1, out, commands)
    return True, masked, chained


def _split_words(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


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


def command_structure(normalized: str) -> CommandStructure | None:
    """The distinct simple commands of one normalized command with their canonical argv.

    ``None`` when the text is empty, over-long or unsplittable (an unterminated quote,
    substitution or here-document): nothing is then known about its parts.
    """

    if type(normalized) is not str or not normalized or len(normalized) > _MAX_TEXT_CHARS:
        return None
    collected: list[str] = []
    commands: list[SimpleCommand] = []
    splittable, masked, chained = _collect(normalized, 0, collected, commands)
    if not splittable:
        return None
    distinct: dict[str, SimpleCommand] = {}
    for item in commands:
        if item.text and "\x00" not in item.text:
            previous = distinct.get(item.text)
            distinct[item.text] = (
                item
                if previous is None
                else SimpleCommand(item.text, item.words, previous.writes or item.writes)
            )
    composition = "masked" if masked else "and_chain" if chained else "single"
    compound = masked or chained or len(distinct) > 1
    return CommandStructure(tuple(distinct.values()), composition, compound)


# ---------------------------------------------------------------------------------------------
# Canonical argv and its commitments (ADR-045)
# ---------------------------------------------------------------------------------------------

_PYTHON_NAME_RE: Final = re.compile(r"^python(?:[0-9]+(?:\.[0-9]+)*)?$", re.ASCII)
_DURATION_RE: Final = re.compile(r"^[0-9]+(?:\.[0-9]+)?[smhd]?$", re.ASCII)
_NICE_LEVEL_RE: Final = re.compile(r"^-[0-9]+$", re.ASCII)
_PLAIN_WRAPPERS: Final = frozenset({"nohup", "command", "exec", "time", "setsid", "builtin"})
_RUN_LAUNCHERS: Final = frozenset({"uv", "poetry", "pipenv", "pdm", "hatch", "rye"})
_RUN_SCRIPT_OPTIONS: Final = frozenset({"--script", "-s", "--gui-script"})
# ``uv run`` options that take a separate value (``uv run --with numpy python x.py``).
_RUN_OPTIONS_WITH_VALUE: Final = frozenset(
    {
        "--with",
        "-w",
        "--with-editable",
        "--with-requirements",
        "--python",
        "-p",
        "--project",
        "--directory",
        "--env-file",
        "--extra",
        "--group",
        "--only-group",
        "--no-group",
        "--package",
        "--index",
        "--index-url",
        "--default-index",
        "--extra-index-url",
        "--find-links",
        "-f",
        "--index-strategy",
        "--config-setting",
        "-C",
        "--resolution",
        "--prerelease",
        "--exclude-newer",
        "--link-mode",
        "--cache-dir",
        "--color",
        "--config-file",
        "-e",
        "--env",
    }
)
# Python interpreter options that change nothing about what is verified. ``-O``/``-OO`` (asserts
# disabled), ``-W``/``-X`` (warnings as errors, dev mode) and ``-E``/``-I``/``-s``/``-S`` (import
# and environment) can change a verifier's outcome, so they stay in the canonical argv.
_PYTHON_NEUTRAL_OPTIONS: Final = frozenset({"-u", "-B", "-q"})
_MAX_WRAPPER_ROUNDS: Final = 8
_SCENE_SETTING: Final = frozenset({"cd", "pushd", "export", "source", "."})
# Shell builtins that never verify anything: no canonical commitment is spent on them.
_NEVER_VERIFICATION: Final = frozenset(
    {"cd", "pwd", "echo", "printf", "true", "false", "export", "set", "unset", "source", ".", ":"}
)


def _basename(word: str) -> str:
    return word.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


def _drop_options(words: list[str], with_operand: frozenset[str], flags: frozenset[str]) -> None:
    """Drop leading options of a wrapper in place: ``flags`` alone, ``with_operand`` plus operand."""

    while words and words[0].startswith("-") and words[0] != "-":
        option = words[0]
        if option == "--":
            words.pop(0)
            return
        name = option.partition("=")[0]
        if name in with_operand and "=" not in option:
            del words[:2]
        elif name in with_operand or name in flags or option.startswith("--"):
            words.pop(0)
        elif len(option) > 2 and option[:2] in with_operand:
            words.pop(0)  # attached operand: ``-s9``
        else:
            words.pop(0)


def _strip_one_wrapper(words: list[str], *, launchers: bool = True) -> bool:
    """Drop one leading wrapper (and its own options) from *words* in place; ``True`` if dropped.

    ``launchers=False`` keeps a package-manager ``run`` launcher (``uv run``, ``poetry run`` ...)
    in place: it syncs, and with ``--upgrade`` rewrites, the lock file and the environment before it
    runs the command, so it is not a transparent wrapper to a caller that must not treat a wrapped
    read as read-only (tb4n3 RC-6, ``domain.observation_selection``).
    """

    if not words:
        return False
    if _ASSIGNMENT_RE.match(words[0]):
        words.pop(0)
        return True
    head = _basename(words[0])
    if head in _PLAIN_WRAPPERS:
        words.pop(0)
        if head == "time" and words[:1] == ["-p"]:
            words.pop(0)
        return True
    if head == "env":
        words.pop(0)
        while words and (words[0].startswith("-") or _ASSIGNMENT_RE.match(words[0])):
            option = words.pop(0)
            if option in _ENV_OPTIONS_WITH_OPERAND and words:
                words.pop(0)
        return True
    if head == "nice":
        words.pop(0)
        if words[:1] in (["-n"], ["--adjustment"]) and len(words) >= 2:
            del words[:2]
        elif words and (_NICE_LEVEL_RE.match(words[0]) or words[0].startswith("--adjustment=")):
            words.pop(0)
        return True
    if head == "ionice":
        words.pop(0)
        _drop_options(
            words,
            frozenset({"-c", "-n", "-p", "-P", "-u", "--class", "--classdata"}),
            frozenset({"-t", "--ignore"}),
        )
        return True
    if head == "stdbuf":
        words.pop(0)
        _drop_options(
            words,
            frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}),
            frozenset(),
        )
        return True
    if head == "timeout":
        words.pop(0)
        _drop_options(
            words,
            frozenset({"-k", "-s", "--kill-after", "--signal"}),
            frozenset({"--foreground", "--preserve-status", "-v", "--verbose"}),
        )
        if words and _DURATION_RE.match(words[0]):
            words.pop(0)
        return True
    if launchers and head in _RUN_LAUNCHERS and words[1:2] == ["run"]:
        if any(word in _RUN_SCRIPT_OPTIONS for word in words[2:]):
            # ``uv run --script build_model.py`` runs the agent's own script by its launcher.
            return False
        del words[:2]
        while words and words[0].startswith("-"):
            option = words.pop(0)
            if option == "--":
                break
            if option in _RUN_OPTIONS_WITH_VALUE and words:
                words.pop(0)
        return True
    return False


def strip_wrappers(words: Sequence[str], *, launchers: bool = True) -> list[str]:
    """*words* without the leading assignments and wrappers that do not change what is run.

    The wrappers are those ``canonical_words`` lists. argv[0] keeps its path and spelling, so a
    caller that classifies a command by its program (``domain.observation_selection``) can still
    tell ``/usr/bin/pytest`` from the agent's own ``./pytest``. With ``launchers=False`` a
    package-manager ``run`` launcher stays at the head, for a caller that classifies it itself.
    """

    rest = [word for word in words if type(word) is str]
    for _ in range(_MAX_WRAPPER_ROUNDS):
        if not _strip_one_wrapper(rest, launchers=launchers):
            break
    return rest


def canonical_words(words: Sequence[str]) -> tuple[str, ...]:
    """The canonical argv of one simple command (ADR-045); ``()`` when nothing is left.

    Drops leading ``VAR=value`` assignments and the wrappers that do not change what is run
    (``timeout``, ``nice``, ``ionice``, ``nohup``, ``stdbuf``, ``env``, ``setsid``, ``time``,
    ``command``, ``exec`` and ``uv``/``poetry``/``pipenv``/``pdm``/``hatch``/``rye run``), reduces
    argv[0] to its basename, ``python3`` and ``pythonX.Y`` to ``python`` (dropping interpreter
    options that cannot change the outcome: ``-u``, ``-B``, ``-q``), ``python -m pytest`` and ``py.test`` to
    ``pytest``. Arguments are never reordered, rewritten or dropped otherwise: two commands that
    run different things never share a canonical form, and a missed equivalence only keeps two
    forms apart.
    """

    rest = strip_wrappers(words)
    if not rest:
        return ()
    head = _basename(rest[0]) or rest[0]
    if _PYTHON_NAME_RE.fullmatch(head) is not None:
        head = "python"
        arguments = rest[1:]
        while arguments and arguments[0] in _PYTHON_NEUTRAL_OPTIONS:
            arguments.pop(0)
        if arguments[:2] == ["-m", "pytest"]:
            return ("pytest", *arguments[2:])
        if arguments[:1] == ["-mpytest"]:
            return ("pytest", *arguments[1:])
        return (head, *arguments)
    if head == "py.test":
        head = "pytest"
    return (head, *rest[1:])


def canonical_commitment(key_material: bytes, kind: str, payload: str) -> str:
    """The domain-separated keyed commitment to one canonical form (never a segment commitment)."""

    if kind not in CANONICAL_KINDS or type(key_material) is not bytes:
        raise ValueError("canonical_commitment_invalid")
    if not 16 <= len(key_material) <= 64 or type(payload) is not str or "\x00" in payload:
        raise ValueError("canonical_commitment_invalid")
    digest = hmac.new(
        key_material,
        _CANONICAL_DOMAIN + kind.encode("ascii") + b"\x00" + payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"


def _joined(words: Sequence[str]) -> str:
    return "\x1f".join(words)


def _flag_payload(words: Sequence[str], token: str) -> str:
    return f"{words[0]}\x1f{token}"


def canonical_command_commitments(
    key_material: bytes, argv: Sequence[str]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """``(full, prefixes, flags)`` canonical commitments of one simple command's argv.

    ``full`` is one commitment to the whole canonical argv; ``prefixes`` one per leading run of
    two or more arguments shorter than the whole (up to ``_MAX_PREFIX_TOKENS``), so a planned
    command that is the start of a longer run is recognised; ``flags`` one per distinct argument
    after argv[0], keyed with argv[0], so the planned program with all of its planned flags is
    recognised in any order. A command of a single argument has only ``full``.
    """

    words = canonical_words(argv)
    if not words:
        return (), (), ()
    full = (canonical_commitment(key_material, "full", _joined(words)),)
    prefixes = tuple(
        canonical_commitment(key_material, "prefix", _joined(words[:size]))
        for size in range(2, min(len(words) - 1, _MAX_PREFIX_TOKENS) + 1)
    )
    tokens = tuple(
        dict.fromkeys(token for token in words[1:] if 0 < len(token) <= _MAX_TOKEN_CHARS)
    )[:_MAX_FLAG_TOKENS]
    flags = tuple(
        canonical_commitment(key_material, "flag", _flag_payload(words, token)) for token in tokens
    )
    return full, prefixes, flags


@dataclass(frozen=True, slots=True)
class PlannedSegment:
    """The probes of one planned simple command, ready to test against an observed run.

    ``exact`` is the segment's own keyed commitment (what ``command_segment_commitments`` has
    always committed); ``full`` its canonical whole; ``prefix`` the prefix commitment of the
    entire planned argv (``None`` under two arguments); ``flags`` one commitment per planned
    argument after argv[0] (empty under two arguments).
    """

    exact: str
    full: str | None
    prefix: str | None
    flags: tuple[str, ...]
    # The command only sets the scene for the next one (``cd``, ``export``): a run of the other
    # commands matches without it.
    scene: bool = False
    # The segment commitment of the canonical argv spelled as plain text: it is what a run whose
    # own text already is its canonical form committed (such a run omits its ``full`` twin).
    canonical_text: str | None = None


def planned_segments(key_material: bytes, normalized: str) -> tuple[PlannedSegment, ...] | None:
    """Probes for each simple command of a planned command, or ``None`` when unsplittable."""

    structure = command_structure(normalized)
    if structure is None:
        return None
    output: list[PlannedSegment] = []
    for command in structure.commands:
        words = command.words
        if not words:
            continue
        flags: tuple[str, ...] = ()
        prefix: str | None = None
        if len(words) >= 2:
            prefix = canonical_commitment(key_material, "prefix", _joined(words))
            flags = tuple(
                canonical_commitment(key_material, "flag", _flag_payload(words, token))
                for token in dict.fromkeys(words[1:])
                if 0 < len(token) <= _MAX_TOKEN_CHARS
            )
        output.append(
            PlannedSegment(
                observed_command_commitment(key_material, command.text),
                canonical_commitment(key_material, "full", _joined(words)),
                prefix,
                flags,
                bool(_SCENE_SETTING.intersection(words[:1])),
                # Plain text only when it is unambiguous: ``pytest -k "foo bar"`` joined is
                # ``pytest -k foo bar``, which is another command's text.
                None
                if any(_AMBIGUOUS_WORD_RE.search(word) for word in words)
                else observed_command_commitment(key_material, " ".join(words)),
            )
        )
    return tuple(output)


def exact_segment_commitments(
    key_material: bytes, normalized: str
) -> tuple[tuple[str, ...], str] | None:
    """Sorted keyed commitments to ``normalized``'s segments, and its composition, or ``None``.

    The whole-command commitment is never repeated here. Beyond ``MAX_SEGMENT_COMMITMENTS``
    distinct segments only the first and last halves in command order are committed. These are
    the commitments planned-verification matching has always compared, without the canonical
    ones (``command_segment_commitments`` adds those on the observed side).
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


def command_segment_commitments(
    key_material: bytes, normalized: str
) -> tuple[tuple[str, ...], str] | None:
    """What a hook commits beside the whole command: segments and canonical forms (ADR-045).

    The sorted keyed commitments to ``normalized``'s segments (``exact_segment_commitments``)
    together with the domain-separated canonical commitments of every simple command, at most
    ``MAX_CANONICAL_COMMITMENTS`` of them: the ``full`` forms first, then prefixes, then flags, so
    a bound only ever costs the looser matches. Also returns the composition. A command with
    nothing to add (an unsplittable one, or a simple command whose canonical form is itself and
    has no further arguments) returns ``None``, as it always did.
    """

    structure = command_structure(normalized)
    if structure is None:
        return None
    whole = observed_command_commitment(key_material, normalized)
    exact = exact_segment_commitments(key_material, normalized)
    commitments = [] if exact is None else list(exact[0])
    ranked: list[tuple[int, int, str]] = []
    for order, command in enumerate(structure.commands):
        if not command.words or command.words[0] in _NEVER_VERIFICATION:
            continue
        full, prefixes, flags = canonical_command_commitments(key_material, command.words)
        if " ".join(command.words) == command.text:
            # The segment's own commitment already identifies it; a ``full`` twin adds nothing.
            full = ()
        ranked.extend((0, order, value) for value in full)
        ranked.extend((1, order, value) for value in prefixes)
        ranked.extend((2, order, value) for value in flags)
    taken = dict.fromkeys(value for _tier, _order, value in sorted(ranked))
    canonical = [value for value in taken if value != whole and value not in commitments]
    merged = sorted({*commitments, *canonical[:MAX_CANONICAL_COMMITMENTS]})
    if not merged:
        return None
    composition = exact[1] if exact is not None else structure.composition
    return tuple(merged), composition


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
