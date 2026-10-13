"""Every surface names the same frontier source (tb4n5, issue #1048, ADR-047).

#1054 made a status read before a write optional and tested only the sentence it changed. Three
other surfaces still said where the frontier comes from - "Read it from `status`" in the
publication policy, "returned by status" in the field description every write tool advertises,
and "Call status to read the current frontier" in the ``expected_frontier_required`` error - so
agents kept reading status before 85 of 87 state-sensitive publishes. This scans every shipped
surface for that instruction and checks the ones that state the rule name the held frontier.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Final, cast

from yoetz.application.publish_work import _event_invalid  # pyright: ignore[reportPrivateUsage]
from yoetz.mcp.descriptors import TOOL_DESCRIPTORS
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.errors import REASON_CODE_CONTINUATIONS
from yoetz.protocol.recovery import RECOVERY_DIRECTIVES

_REPO_ROOT: Final = Path(__file__).resolve().parents[3]
# "Use the frontier status returned" in any spelling: the instruction #1048 retires. A genuine
# conflict (``frontier_changed``) still sends the agent to status, so that wording is not banned.
_STATUS_AS_FRONTIER_SOURCE: Final = (
    re.compile(r"(?:frontier|head digest)[^.]{0,40}returned by `?status", re.IGNORECASE),
    re.compile(r"read (?:it|the frontier|the current frontier) from `?status", re.IGNORECASE),
    re.compile(r"frontier must come from[^.]*`?status", re.IGNORECASE),
    re.compile(r"frontier[^.]{0,40}\bfrom `?status`?(?! view)", re.IGNORECASE),
)


def _collapsed(text: str) -> str:
    return " ".join(text.split())


def _shipped_pages() -> Iterator[tuple[str, str]]:
    roots = [
        *sorted((_REPO_ROOT / "guidance").glob("*.md")),
        *sorted((_REPO_ROOT / "docs" / "usage").glob("*.md")),
        *sorted((_REPO_ROOT / "skills").glob("*/yoetz/SKILL.md")),
    ]
    for path in roots:
        yield str(path.relative_to(_REPO_ROOT)), _collapsed(path.read_text(encoding="utf-8"))


def _description_strings(node: JsonValue) -> Iterator[str]:
    if isinstance(node, dict):
        mapping = node
        description = mapping.get("description")
        if type(description) is str:
            yield description
        for value in mapping.values():
            yield from _description_strings(value)
    elif isinstance(node, (list, tuple)):
        for value in cast(list[JsonValue], node):
            yield from _description_strings(value)


def _tool_texts() -> Iterator[tuple[str, str]]:
    for profile, descriptors in TOOL_DESCRIPTORS.items():
        for descriptor in descriptors:
            yield f"{profile}:{descriptor.name}", descriptor.description
            schema = cast(JsonValue, dict(descriptor.input_schema))
            for text in _description_strings(schema):
                yield f"{profile}:{descriptor.name}:schema", text


def _missing_frontier_texts() -> Iterator[tuple[str, str]]:
    error = _event_invalid("expected_frontier_required", retryable=True)
    yield "expected_frontier_required message", error.message
    token = REASON_CODE_CONTINUATIONS["expected_frontier_required"]
    directive = RECOVERY_DIRECTIVES[token]
    yield f"{token} directive", directive.directive
    yield f"{token} nudge", directive.nudge or ""


def test_no_shipped_surface_names_status_as_the_frontier_source() -> None:
    offenders: list[str] = []
    for source, text in (*_shipped_pages(), *_tool_texts(), *_missing_frontier_texts()):
        for pattern in _STATUS_AS_FRONTIER_SOURCE:
            match = pattern.search(text)
            if match is not None:
                offenders.append(f"{source}: {match.group(0)!r}")
    assert offenders == []


def test_every_advertised_expected_frontier_names_the_held_frontier() -> None:
    seen = 0
    for profile, descriptors in TOOL_DESCRIPTORS.items():
        for descriptor in descriptors:
            properties = descriptor.input_schema.get("properties")
            if not isinstance(properties, dict):
                continue
            field = properties.get("expected_frontier")
            if not isinstance(field, dict):
                continue
            seen += 1
            text = cast(str, field["description"])
            assert "start returned" in text, (profile, descriptor.name)
            assert "result_frontier" in text, (profile, descriptor.name)
            assert "Read status only when you hold none" in text, (profile, descriptor.name)
    # publish_work, check, respond and receipt carry it on both route profiles.
    assert seen >= 8


def test_a_missing_frontier_is_answered_with_the_held_one_not_a_refresh() -> None:
    assert REASON_CODE_CONTINUATIONS["expected_frontier_required"] == "frontier_held_required"
    # A genuine conflict still refreshes from status.
    assert REASON_CODE_CONTINUATIONS["frontier_changed"] == "frontier_refresh_required"
    for source, text in _missing_frontier_texts():
        if source.endswith("nudge"):
            continue
        assert "start" in text, source
        assert "result_frontier" in text, source
        assert "status to read" not in text.lower(), source
        assert "read status for the current frontier" not in text.lower(), source


def test_the_rule_is_stated_where_agents_author_writes() -> None:
    policy = dict(_shipped_pages())["guidance/publication-policy.md"]
    assert "the first plan batch uses the `frontier` that `start` returned" in policy
    assert "the `result_frontier` of your last accepted `publish_work`, `check` or `respond`" in (
        policy
    )
    assert "read `status` only when you hold no frontier, or after a `frontier_changed`" in policy
    card = dict(_shipped_pages())["guidance/agent-instructions.md"]
    assert (
        "send each returned frontier as the next `expected_frontier` (first plan: `start`'s)"
        in card
    )
    # The read that answers "what is left and why" is named, not forced.
    assert "What is left and why: `check` `mode: inspect` (records nothing)." in card
    templates = dict(_shipped_pages())["guidance/request-templates.md"]
    assert "Send this first plan with `expected_frontier` set to the `frontier` your `start`" in (
        templates
    )
    assert "Never send `expected_frontier: null` on a state-sensitive batch." in templates
