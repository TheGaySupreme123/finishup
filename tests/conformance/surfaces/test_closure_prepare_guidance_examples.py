"""The shipped closure preparation examples stay valid against the MCP request schema."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from yoetz.mcp.resources import read_resource
from yoetz.protocol.models import ClosurePrepareRequest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CANONICAL = _REPO_ROOT / "guidance" / "request-templates.md"
_PACKAGED = _REPO_ROOT / "src" / "yoetz" / "resources" / "guidance" / "request-templates.md"
_JSON_FENCE = re.compile(r"```json\s*\n(?P<body>\{.*?\})\n```", re.DOTALL)
_REQUEST_KEYS = frozenset(("session_id", "writer_id", "selection"))


def _closure_examples(document: str) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    for match in _JSON_FENCE.finditer(document):
        value = json.loads(match.group("body"))
        if isinstance(value, dict) and _REQUEST_KEYS <= value.keys():
            examples.append(cast(dict[str, Any], value))
    return examples


def test_canonical_and_packaged_closure_examples_validate() -> None:
    canonical = _CANONICAL.read_text(encoding="utf-8")
    packaged = _PACKAGED.read_text(encoding="utf-8")
    assert packaged == canonical
    assert read_resource("yoetz://guidance/request-templates.md").decode("utf-8") == canonical

    examples = _closure_examples(canonical)
    assert len(examples) >= 2
    phases: set[str] = set()
    for example in examples:
        phases.add(ClosurePrepareRequest.model_validate(example).selection.phase)
    assert {"inventory", "attempt"} <= phases
