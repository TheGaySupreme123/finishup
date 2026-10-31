"""#1248 P1: FinishUP's own markers never produce a hit, at any escaping depth (P-D1).

The TB4 full run lost every AI-powered review of two tasks because FinishUP's own replacement
marker, followed by an encoded line break and the next line, was re-detected as a credential once
the reviewer conversation encoded the packet a second time (#1138). The marker is now exempt by
the span FinishUP recorded writing it, and the conversation is scanned per message (P-D2). These cases
send a value FinishUP replaced, with the span it recorded, through ``encode_reviewer_exchange`` at
conversation depths 1 to 3, followed by each line shape the TB4 investigation listed.
"""

from __future__ import annotations

from typing import cast

import pytest

from finishup.adapters.privacy.local_enforcer import LocalPrivacyEnforcer
from finishup.application.egress import (
    PrivacyCoordinator,
    _resume_scan_is_clean,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.privacy import CredentialHeuristic
from finishup.observability.marker_spans import (
    MarkerSpans,
    container_marker_spans,
    encoded_string_spans,
    packet_rows_marker_spans,
    shift_marker_spans,
)
from finishup.observability.privacy import (
    EGRESS_CREDENTIAL_PLACEHOLDER,
    redact_heuristic_spans,
    redact_heuristic_spans_marked,
    scan_for_sensitive_content,
)
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.privacy import (
    HumanAuthorityCapability,
    OutboundGatewayPort,
    PrivacyAuditPort,
    PrivacyPolicyStorePort,
)
from finishup.ports.semantic import decode_reviewer_exchange, encode_reviewer_exchange
from finishup.protocol.canonical import canonical_encode
from unit.application.test_egress_origin_operation import (
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _Gateway,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _Store,  # pyright: ignore[reportPrivateUsage]
)
from unit.privacy.test_planted_credentials_semantic_arm import (
    _Audit,  # pyright: ignore[reportPrivateUsage]
)

# What follows the replaced value's line, as #1138 lists it.
FOLLOWING = {
    "indented_line": "\n    role: admin\n",
    "column_0_line": "\nDB_USER=app\n",
    "blank_line": "\n\nretries: 3\n",
    "crlf": "\r\nDB_USER=app\r\n",
    "diff_context_line": "\n unchanged_line = 1\n",
    "diff_plus_line": "\n+DB_USER=app\n",
}
ASSIGNMENTS = ("  password: ", "DB_PASSWORD=", "+password=")
ITEM_ID = "excerpt-evd_10000000-0000-4000-8000-000000000001"


def redacted(text: str) -> tuple[bytes, MarkerSpans]:
    """``text`` as FinishUP's egress pass leaves it, with the spans it recorded writing markers."""

    replaced, count, spans = redact_heuristic_spans_marked(text.encode())
    assert count >= 1 and spans
    return replaced, spans


def packet_for(content: bytes, spans: MarkerSpans, depth: int) -> tuple[bytes, MarkerSpans]:
    """The packet message carrying ``content`` at conversation ``depth`` (1 to 3), and its spans.

    Depth 1 is the text straight in the packet message, depth 2 a packet item's content, depth 3
    a JSON string inside that content (a JSON file under review). The recorded spans travel with
    the text through each encoding, as the minimizer carries them.
    """

    if depth == 1:
        return content, spans
    if depth == 3:
        token = canonical_encode(content.decode())
        prefix = b'{"cfg":'
        spans = shift_marker_spans(encoded_string_spans(token, spans), len(prefix))
        content = prefix + token + b"}"
    packet = canonical_encode(
        {
            "items": [{"content": content.decode(), "item_id": ITEM_ID}],
            "schema": "yoetz.review-packet-case/2",
        }
    )
    return packet, packet_rows_marker_spans(packet, {ITEM_ID: spans})


def exchange(packet: bytes) -> bytes:
    return encode_reviewer_exchange((("system", "review the packet"), ("user", packet.decode())))


def coordinator() -> PrivacyCoordinator:
    return PrivacyCoordinator(
        cast(PrivacyPolicyStorePort, _Store()),
        LocalPrivacyEnforcer(),
        cast(PrivacyAuditPort, _Audit()),
        cast(OutboundGatewayPort, _Gateway()),
        cast(ClockPort, _Clock()),
        cast(IdPort, _Ids()),
        human_authority=HumanAuthorityCapability(
            "established_passphrase", "sha256:" + "8" * 64, 1, "passphrase", 1, True
        ),
    )


def hit(payload: bytes, packet: bytes, spans: MarkerSpans) -> object:
    return coordinator()._reviewer_exchange_hit(  # pyright: ignore[reportPrivateUsage]
        payload, packet, spans, CredentialHeuristic.ENFORCED
    )


def conversation(assignment: str, following: str, depth: int) -> tuple[bytes, bytes, MarkerSpans]:
    content, spans = redacted("config:\n" + assignment + "hunter2" + following)
    packet, packet_spans = packet_for(content, spans, depth)
    return exchange(packet), packet, packet_spans


@pytest.mark.parametrize("depth", (1, 2, 3))
@pytest.mark.parametrize("following", FOLLOWING.values(), ids=FOLLOWING.keys())
@pytest.mark.parametrize("assignment", ASSIGNMENTS)
def test_finishup_markers_never_produce_a_hit_in_the_reviewer_conversation(
    assignment: str, following: str, depth: int
) -> None:
    payload, packet, spans = conversation(assignment, following, depth)
    assert EGRESS_CREDENTIAL_PLACEHOLDER in payload and b"hunter2" not in payload
    # The exact conversation bytes, as the gateway's final scan and the resume rescan see them.
    carried = container_marker_spans(payload, packet, spans)
    assert len(carried) == len(spans)
    assert scan_for_sensitive_content(payload, marker_spans=carried) == ()
    assert redact_heuristic_spans(payload, marker_spans=carried) == (payload, 0)
    # The packet message's decoded content, as the reviewer reads it (#1248 P-D2).
    assert decode_reviewer_exchange(payload)[1][1].encode() == packet
    assert scan_for_sensitive_content(packet, marker_spans=spans) == ()
    assert hit(payload, packet, spans) is None
    assert _resume_scan_is_clean(LocalPrivacyEnforcer(), payload, marker_spans=spans) == ()


@pytest.mark.parametrize("depth", (1, 2, 3))
@pytest.mark.parametrize("following", FOLLOWING.values(), ids=FOLLOWING.keys())
def test_the_same_marker_without_its_recorded_span_is_a_value(following: str, depth: int) -> None:
    # #1248 P-D1: no exemption from text. Content stored before positions were recorded, or a
    # marker an agent typed, is judged like any value; in a packet item that hit withholds the
    # one item (P-D2), anywhere else it refuses the case.
    payload, packet, _spans = conversation("  password: ", following, depth)
    found = hit(payload, packet, ())
    assert found is not None
    assert getattr(found, "withholdable") is (depth > 1)
    if depth > 1:
        assert getattr(found, "item_ids") == frozenset({ITEM_ID})
    assert _resume_scan_is_clean(LocalPrivacyEnforcer(), payload)


@pytest.mark.parametrize("depth", (1, 2, 3))
@pytest.mark.parametrize("following", FOLLOWING.values(), ids=FOLLOWING.keys())
def test_a_real_value_after_the_marker_line_is_still_found(following: str, depth: int) -> None:
    # The exemption is the recorded span alone: a value on the next line is judged as always.
    line_break = "\r\n" if following.startswith("\r\n") else "\n"
    content, spans = redacted("  password: hunter2" + line_break + following)
    content += b"  secret_key: hunter2x" + line_break.encode()
    packet, packet_spans = packet_for(content, spans, depth)
    payload = exchange(packet)
    found = hit(payload, packet, packet_spans)
    assert found is not None
    if depth > 1:
        # Traced to the one packet item that carries it, which is what is withheld.
        assert getattr(found, "item_ids") == frozenset({ITEM_ID})
        assert getattr(found, "withholdable")
    else:
        # Straight in a message (FinishUP's frame or a reply), nothing can be withheld.
        assert not getattr(found, "withholdable")
    assert _resume_scan_is_clean(LocalPrivacyEnforcer(), payload, marker_spans=packet_spans)


def test_only_the_row_a_span_was_recorded_for_is_exempt() -> None:
    # Spans travel out of band, per row; two rows with the same text share nothing.
    content, spans = redacted("  password: hunter2\n")
    packet = canonical_encode(
        {
            "items": [
                {"content": content.decode(), "item_id": ITEM_ID},
                {"content": content.decode(), "item_id": ITEM_ID + "x"},
            ],
            "schema": "yoetz.review-packet-case/2",
        }
    )
    one = packet_rows_marker_spans(packet, {ITEM_ID: spans})
    both = packet_rows_marker_spans(packet, {ITEM_ID: spans, ITEM_ID + "x": spans})
    assert len(one) == 1 and len(both) == 2
    assert scan_for_sensitive_content(packet, marker_spans=one)
    assert scan_for_sensitive_content(packet, marker_spans=both) == ()


def test_finishup_conversation_text_never_produces_a_hit() -> None:
    # #1248 P-D1: FinishUP's own conversation text is scanned like any message and never hits.
    from finishup.adapters.providers.reviewer_reply import REVIEWER_LOOP_INSTRUCTION
    from finishup.application.reviewer_broker import ReadRoot
    from finishup.application.reviewer_loop import (
        FINAL_FORMAT_ERROR,
        FINAL_PHASE,
        FORMAT_ERROR,
        READ_NOT_SERVED,
    )
    from finishup.application.reviewer_run import PACKET_TURN, reviewer_catalog

    catalog = reviewer_catalog((ReadRoot("workspace", "/work"),), 5)
    texts = (
        REVIEWER_LOOP_INSTRUCTION,
        PACKET_TURN,
        catalog,
        FORMAT_ERROR.format(code="schema_mismatch"),
        FINAL_FORMAT_ERROR.format(code="schema_mismatch"),
        FINAL_PHASE,
        READ_NOT_SERVED,
    )
    payload = encode_reviewer_exchange(
        (("system", REVIEWER_LOOP_INSTRUCTION), *(("user", text) for text in texts[1:]))
    )
    for text in texts:
        assert scan_for_sensitive_content(text.encode()) == ()
    assert scan_for_sensitive_content(payload) == ()
