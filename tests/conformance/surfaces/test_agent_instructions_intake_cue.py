"""Tier-zero agent instructions must front-load a self-contained material-task intake cue.

The first 512 bytes of `guidance/agent-instructions.md` are not ordinary prose: `intake_cue_text`
slices that window and trims it back to the last blank line, and the result is injected as
`additionalContext` on every `UserPromptSubmit`. It is the highest-frequency agent-facing text in
the system, so the window is authored deliberately -- the activation trigger, the cadence, and the
honesty floor all have to land inside it, and it has to end on a finished sentence rather than a
dangling heading.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from yoetz.cli.hooks import intake_cue_text
from yoetz.mcp.resources import read_resource

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CANONICAL = _REPO_ROOT / "guidance" / "agent-instructions.md"
_PACKAGED = _REPO_ROOT / "src" / "yoetz" / "resources" / "guidance" / "agent-instructions.md"
_INTAKE_WINDOW = 512
_MATERIAL_TRIGGER = (
    b"Use Yoetz for material multi-step, delegated, resumable, or verification-heavy work."
)
_START_CUE = b"then `start` before substantive work."
_NEW_SESSION_CUE = b"New session: read guidance/discover schemas"
_START_FAIL_CUE = (
    b"If startup fails, follow recovery first; if still blocked, ask for intro and guidance."
)
_TRIVIAL_EXCLUSION = b"Skip trivial questions or edits; never invent a ledger task."
_CADENCE_CUE = b"Cadence: `start` once, `publish_work` per material transition; `receipt` last."
_NO_FALSE_ACTIVATION = b"Never claim Yoetz is active until `start` returns."
_CUE_SENTENCES: Final = (
    _MATERIAL_TRIGGER,
    _START_CUE,
    _NEW_SESSION_CUE,
    _START_FAIL_CUE,
    _TRIVIAL_EXCLUSION,
    _CADENCE_CUE,
    _NO_FALSE_ACTIVATION,
)


def _assert_intake_cue_within_first_512(data: bytes) -> None:
    assert data == data.decode("utf-8").encode("utf-8")
    window = data[:_INTAKE_WINDOW]
    heading_end = data.find(b"\n")
    paragraph_end = data.find(b"\n\n", heading_end + 1)
    assert paragraph_end >= 0 and paragraph_end + 2 <= _INTAKE_WINDOW
    for sentence in _CUE_SENTENCES:
        assert sentence in window, f"missing from the intake window: {sentence!r}"


def test_canonical_agent_instructions_front_load_intake_cue() -> None:
    _assert_intake_cue_within_first_512(_CANONICAL.read_bytes())


def test_packaged_agent_instructions_front_load_intake_cue() -> None:
    packaged = _PACKAGED.read_bytes()
    assert packaged == _CANONICAL.read_bytes()
    _assert_intake_cue_within_first_512(packaged)
    assert packaged == read_resource("yoetz://guidance/agent-instructions.md")


def test_intake_cue_ends_on_a_finished_sentence_not_a_heading() -> None:
    """The 512-byte slice must not strand a heading with no body under it.

    `intake_cue_text` keeps everything up to the *last* blank line inside the window, so a heading
    that happens to fall just under the boundary becomes the final line of every injected cue.
    """

    cue = intake_cue_text()
    last_line = cue.splitlines()[-1].strip()
    assert not last_line.startswith("#"), f"intake cue ends on a bare heading: {last_line!r}"
    assert last_line.endswith("."), f"intake cue ends mid-thought: {last_line!r}"


def test_intake_cue_is_self_contained() -> None:
    """An agent that reads only the injected cue still knows when to act and how often."""

    cue = intake_cue_text().encode("utf-8")
    for sentence in _CUE_SENTENCES:
        assert sentence in cue, f"trimmed out of the delivered cue: {sentence!r}"


def test_agent_instructions_say_not_to_list_resources() -> None:
    """Initialize instructions arrive before the first host list call (issue #173)."""

    text = _CANONICAL.read_text(encoding="utf-8")
    collapsed = " ".join(text.split())
    assert (
        "Do not call `resources/list` or `list_mcp_resources` to find Yoetz guidance" in collapsed
    )
    assert "a list failure is not a missing server or reason to read product source" in collapsed
    assert "call `read_guidance` with the same URI" in collapsed
    assert "Only if that result is also empty" in collapsed
    assert collapsed.index("# Guidance catalog") > collapsed.index(
        "Yoetz is not an enforcement system"
    )
    read_more = text.split("# Read more", 1)[1]
    for uri in (
        "yoetz://guidance/agent-instructions.md",
        "yoetz://guidance/workflow.md",
        "yoetz://guidance/publication-policy.md",
        "yoetz://guidance/coverage-and-receipts.md",
        "yoetz://guidance/request-templates.md",
    ):
        assert f"`{uri}`" in read_more
