"""#1248 P4 (owner decision P-D5): the placeholder is written new and read in both spellings.

New content carries ``[withheld-by-finishup:possible-credential]``. The legacy
``[withheld-by-yoetz:possible-credential]`` is a frozen ADR-048 identifier: every reader accepts it
forever and no pass writes it as a new replacement. The exemption is still the recorded span alone
(P-D1), whatever the spelling; P1's depth and line-shape cases run on the new spelling through
``test_marker_positions``, and these run the same shapes on the legacy one.
"""

from __future__ import annotations

import pytest

import finishup.observability.marker_spans as marker_spans_module
import finishup.observability.privacy as privacy_module
from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer, SecretScanRuleset
from finishup.application.egress import (
    _resume_scan_is_clean,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.receipts import (
    SEMANTIC_REDACTED_VALUES_AGENT_LINE,
    SEMANTIC_REDACTED_VALUES_AGENT_LINE_SHORT,
    semantic_redacted_value_agent_lines,
)
from finishup.observability.marker_spans import container_marker_spans, valid_marker_spans
from finishup.observability.privacy import (
    EGRESS_CREDENTIAL_PLACEHOLDER,
    EGRESS_CREDENTIAL_PLACEHOLDERS,
    LEGACY_EGRESS_CREDENTIAL_PLACEHOLDER,
    redact_encoded_heuristic_spans_marked,
    redact_heuristic_spans_marked,
    redact_sensitive_content,
    scan_for_sensitive_content,
)
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.redacted_values import SemanticRedactedValue
from unit.privacy.test_marker_positions import (
    ASSIGNMENTS,
    FOLLOWING,
    exchange,
    hit,
    packet_for,
)

NEW = b"[withheld-by-finishup:possible-credential]"
LEGACY = b"[withheld-by-yoetz:possible-credential]"


def test_the_placeholder_is_written_in_the_finishup_spelling() -> None:
    assert EGRESS_CREDENTIAL_PLACEHOLDER == NEW
    assert LEGACY_EGRESS_CREDENTIAL_PLACEHOLDER == LEGACY
    assert EGRESS_CREDENTIAL_PLACEHOLDERS == (NEW, LEGACY)
    # Every pass that writes the placeholder writes the new spelling only.
    for text in (b"password=hunter2\n", b'api_key = "hunter2"\n', b"  secret: hunter2\n"):
        replaced, count, spans = redact_heuristic_spans_marked(text)
        assert count == 1 and NEW in replaced and LEGACY not in replaced
        assert [replaced[start:end] for start, end in spans] == [NEW]
        changed, _detected = redact_sensitive_content(text, heuristic_marker=NEW)
        assert NEW in changed and LEGACY not in changed


def test_no_pass_accepts_the_legacy_spelling_as_the_marker_to_write() -> None:
    with pytest.raises(ValueError, match="redaction_marker_invalid"):
        redact_sensitive_content(b"password=hunter2\n", heuristic_marker=LEGACY)


def test_the_span_check_and_the_scanner_know_the_same_markers() -> None:
    exempt = getattr(privacy_module, "_EXEMPT_REPLACEMENT_MARKERS")
    assert getattr(marker_spans_module, "_MARKERS") == exempt == {b"[REDACTED]", NEW, LEGACY}
    data = b"a=" + LEGACY + b" b=" + NEW + b" c=[REDACTED]"
    spans = tuple(
        (data.index(marker), data.index(marker) + len(marker))
        for marker in (LEGACY, NEW, b"[REDACTED]")
    )
    assert valid_marker_spans(data, spans) == tuple(sorted(spans))
    # A span that does not cover exactly one marker still grants nothing.
    assert valid_marker_spans(data, ((spans[0][0], spans[0][1] - 1),)) == ()


def _legacy_conversation(
    assignment: str, following: str, depth: int, *, recorded: bool = True
) -> tuple[bytes, bytes, tuple[tuple[int, int], ...]]:
    """A legacy marker stored at a recorded position, sent through the reviewer conversation."""

    content = ("config:\n" + assignment).encode() + LEGACY + following.encode()
    start = content.index(LEGACY)
    spans = ((start, start + len(LEGACY)),) if recorded else ()
    packet, packet_spans = packet_for(content, spans, depth)
    return exchange(packet), packet, packet_spans


@pytest.mark.parametrize("depth", (1, 2, 3))
@pytest.mark.parametrize("following", FOLLOWING.values(), ids=FOLLOWING.keys())
@pytest.mark.parametrize("assignment", ASSIGNMENTS)
def test_a_recorded_legacy_marker_never_produces_a_hit(
    assignment: str, following: str, depth: int
) -> None:
    payload, packet, spans = _legacy_conversation(assignment, following, depth)
    carried = container_marker_spans(payload, packet, spans)
    assert len(carried) == len(spans) == 1
    assert scan_for_sensitive_content(payload, marker_spans=carried) == ()
    assert scan_for_sensitive_content(packet, marker_spans=spans) == ()
    assert hit(payload, packet, spans) is None
    assert _resume_scan_is_clean(LocalPrivacyEnforcer(), payload, marker_spans=spans) == ()


@pytest.mark.parametrize("depth", (1, 2, 3))
def test_an_unrecorded_legacy_marker_is_judged_like_any_value(depth: int) -> None:
    # P-D1 is unchanged by the second spelling: no exemption is ever read from the text.
    payload, packet, _spans = _legacy_conversation(
        "  password: ", FOLLOWING["indented_line"], depth, recorded=False
    )
    assert hit(payload, packet, ()) is not None


@pytest.mark.parametrize(
    ("stored", "kept"),
    (
        (b"password=" + LEGACY + b"\n    role: admin\n", LEGACY),
        (b'API_KEY="' + LEGACY + b'"\n', LEGACY),
        (b"password=" + NEW + b"\nDB_USER=app\n", NEW),
        # FinishUP's own [REDACTED] in a value position keeps reading as the placeholder.
        (b"password=[REDACTED]\n", NEW),
    ),
)
def test_an_unrecorded_placeholder_is_replaced_in_the_spelling_it_was_stored_with(
    stored: bytes, kept: bytes
) -> None:
    replaced, count, spans = redact_heuristic_spans_marked(stored)
    assert count == 1
    assert [replaced[start:end] for start, end in spans] == [kept]
    if kept in stored:
        # Stored bytes are never rewritten: the result is the input, now with its span recorded.
        assert replaced == stored
    assert scan_for_sensitive_content(replaced, marker_spans=spans) == ()


def test_an_encoded_legacy_marker_keeps_its_spelling_too() -> None:
    stored = canonical_encode({"cfg": "password=" + LEGACY.decode() + "\n  role: admin"})
    marked = redact_encoded_heuristic_spans_marked(stored)
    assert marked is not None
    replaced, _count, spans = marked
    assert NEW not in replaced and LEGACY in replaced
    assert [replaced[start:end] for start, end in spans] == [LEGACY]


def test_a_legacy_marker_with_a_suffix_is_a_value_and_gets_the_new_spelling() -> None:
    # The suffix may be secret material: it is replaced, and anything written is new content.
    stored = b"TOKEN=" + LEGACY + b"realsecret1\n"
    assert scan_for_sensitive_content(stored)
    replaced, count, spans = redact_heuristic_spans_marked(stored)
    assert count == 1 and b"realsecret1" not in replaced
    assert [replaced[start:end] for start, end in spans] == [NEW]


def test_the_scanner_profile_moved_so_a_resume_never_mixes_spellings() -> None:
    ruleset = SecretScanRuleset()
    assert ruleset.version == "observability-sensitive-content-v5"
    assert ruleset.profile_digest != (
        "sha256:8710381761bf88c0585e3fc081cbfc7571ecf946eb1828139175eb72de251f9c"
    )


def test_the_agent_lines_name_both_spellings() -> None:
    for line in (SEMANTIC_REDACTED_VALUES_AGENT_LINE, SEMANTIC_REDACTED_VALUES_AGENT_LINE_SHORT):
        assert NEW.decode() in line and LEGACY.decode() in line
        assert line.index(NEW.decode()) < line.index(LEGACY.decode())
    values = (SemanticRedactedValue("excerpt-1", "value_replaced", (3,)),)
    assert semantic_redacted_value_agent_lines(values) == (SEMANTIC_REDACTED_VALUES_AGENT_LINE,)


def test_the_reviewer_loop_instruction_names_both_spellings_within_its_ceiling() -> None:
    from finishup.adapters.providers.reviewer_reply import REVIEWER_LOOP_INSTRUCTION

    assert "[withheld-by-finishup:...]" in REVIEWER_LOOP_INSTRUCTION
    assert "[withheld-by-yoetz:...]" in REVIEWER_LOOP_INSTRUCTION
    # #1203: the loop instruction keeps its ceiling, so the minimal policy keeps its read room.
    assert len(REVIEWER_LOOP_INSTRUCTION.encode()) <= 7639
