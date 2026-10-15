"""User-facing text never says "deterministic" (owner naming rule, ADR-049).

The no-AI mode is "FinishUP", or "local" as a short label; the add-on is "AI-powered review".
Wire values keep their released spellings (``deterministic_only``, ``deterministic_mode``,
``no_unresolved_deterministic_findings``, the ``deterministic`` finding origin, the checkpoint
media type), so this guard ignores those tokens and identifiers. It scans:

- prose in guidance, the host skills, ``docs/usage`` and the README (outside code spans);
- every non-docstring string literal in ``src/finishup`` that reads as prose: what the CLI, the
  terminal interface, hooks, MCP summaries, descriptors, receipts and setup print.

Model-facing reviewer instructions (``adapters/providers/openai_responses.py``) are not shown to
users and are pinned by their own instruction tests, so they are excluded; frozen fixtures,
released schemas and migrations are not scanned.
"""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path
from typing import Final

_REPO: Final = Path(__file__).resolve().parents[3]
_WORD: Final = re.compile(r"determinis", re.IGNORECASE)
_CODE_SPAN: Final = re.compile(r"`[^`\n]*`")
_IDENTIFIER: Final = re.compile(r"^[A-Za-z0-9_./:#+-]*$")
_WIRE_TOKENS: Final = re.compile(
    r"\b(?:deterministic_only|deterministic_mode|no_unresolved_deterministic_findings)\b"
    r"|vnd\.yoetz\.deterministic-result"
)
_MODEL_FACING: Final = frozenset({"src/finishup/adapters/providers/openai_responses.py"})


def _tracked(*patterns: str) -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", *patterns], cwd=_REPO, check=True, capture_output=True, text=True
    ).stdout.split()
    return [_REPO / name for name in sorted(set(listed))]


def test_user_facing_markdown_never_says_deterministic() -> None:
    offenders: list[str] = []
    for path in _tracked(
        "guidance/*.md", "skills/*/finishup/SKILL.md", "docs/usage/*.md", "README.md"
    ):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            prose = _CODE_SPAN.sub("", line)
            if _WORD.search(prose):
                offenders.append(f"{path.relative_to(_REPO)}:{number}: {line.strip()[:120]}")
    assert offenders == [], "\n".join(offenders)


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


def test_user_facing_strings_in_the_product_never_say_deterministic() -> None:
    offenders: list[str] = []
    for path in _tracked("src/finishup/*.py", "src/finishup/**/*.py"):
        relative = path.relative_to(_REPO).as_posix()
        if relative in _MODEL_FACING or "/resources/" in relative:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = _docstring_ids(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if id(node) in docstrings or _IDENTIFIER.match(node.value):
                continue
            if _WORD.search(_WIRE_TOKENS.sub("", node.value)):
                offenders.append(f"{relative}:{node.lineno}: {node.value[:120]!r}")
    assert offenders == [], "\n".join(offenders)


def test_the_guard_sees_a_reintroduced_phrase() -> None:
    """The scanners would catch the wording this sweep removed."""

    assert _WORD.search(_CODE_SPAN.sub("", "No issue detected within deterministic coverage"))
    assert not _WORD.search(_CODE_SPAN.sub("", "use `deterministic_only` only for local work"))
    assert _WORD.search(_WIRE_TOKENS.sub("", "within deterministic coverage; deterministic_only"))
    assert not _WORD.search(_WIRE_TOKENS.sub("", "switch to deterministic_only"))
