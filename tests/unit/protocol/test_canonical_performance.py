"""Latency fence for the canonical codec on a realistically-sized document (#290).

The observation state file reaches 1 MiB, and every hook pass parses it once
and encodes it at least twice. The per-character Python loops that used to
implement string validation/escaping made those operations ~70x slower than
the stdlib on the same bytes, which dominated the hook 'store' stage. A
fixture-sized document passes any implementation trivially, so this fence
measures a ~1 MiB document and bounds the cost relative to the stdlib codec
on the same machine. Paired CPU-time samples exclude runner descheduling,
and the median limits the influence of an isolated noisy sample.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from statistics import median

from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

# Measured on this document: the regressed implementation ran 37-48x stdlib,
# the current one 11-13x. The fence sits above the current ratio with margin
# and far below the regressed one, so it catches a return to per-character
# work without flapping on ordinary hardware variance.
_MAX_STDLIB_RATIO = 20.0


def _realistic_document() -> dict[str, JsonValue]:
    """~1 MiB of state-file-shaped JSON: hashes, tokens, and some escapes."""

    digest = "hmac-sha256:" + "ab" * 32
    envelopes: list[JsonValue] = [
        {
            "session_commitment": digest,
            "event_kind": "PreToolUse",
            "source_identity": f"hook:{index}:{digest}",
            "structural_payload": {
                "tool_name": "shell",
                "tool_call_id": f"call_{index}",
                "command": 'rg --json "needle" ./src\n' * 4,
            },
            "gap_codes": ["unpaired_event"],
        }
        for index in range(900)
    ]
    return {
        "dedup": [f"{digest}:{index}" for index in range(2800)],
        "envelopes": envelopes,
        "quarantine": envelopes[:300],
        "stream_partials": {digest: "b64:" + "QUJD" * 4_000},
    }


def _paired_cpu_ratio(reference: Callable[[], object], candidate: Callable[[], object]) -> float:
    # Warm both paths before measuring. Each adjacent pair sees similar CPU/cache
    # conditions; alternate order so neither path always pays the first-run cost.
    reference()
    candidate()
    ratios: list[float] = []
    for sample in range(5):
        durations: dict[str, int] = {}
        pair = (("reference", reference), ("candidate", candidate))
        for name, operation in pair if sample % 2 == 0 else reversed(pair):
            started = time.process_time_ns()
            for _ in range(3):
                operation()
            durations[name] = time.process_time_ns() - started
        assert durations["reference"] > 0
        ratios.append(durations["candidate"] / durations["reference"])
    return median(ratios)


def test_parse_and_encode_stay_within_ratio_of_stdlib_on_large_state() -> None:
    document = _realistic_document()
    raw = canonical_encode(document)
    assert len(raw) > 700_000

    assert (
        _paired_cpu_ratio(lambda: json.loads(raw), lambda: strict_json_parse(raw))
        <= _MAX_STDLIB_RATIO
    )

    assert (
        _paired_cpu_ratio(
            lambda: json.dumps(document, separators=(",", ":"), sort_keys=True).encode(),
            lambda: canonical_encode(document),
        )
        <= _MAX_STDLIB_RATIO
    )


def test_fast_string_paths_are_output_identical() -> None:
    """Escape-needing and plain strings encode byte-identically to the spec."""

    tricky = {
        "plain": "ordinary token-text_1234:/+-",
        "escapes": 'quote " backslash \\ tab \t newline \n bell \x07 unit \x1f',
        "unicode": "διακριτικά — em—dash é中文",
        "empty": "",
    }
    encoded = canonical_encode(tricky)
    assert encoded == (
        b'{"empty":"","escapes":"quote \\" backslash \\\\ tab \\t newline \\n '
        b'bell \\u0007 unit \\u001f","plain":"ordinary token-text_1234:/+-",'
        b'"unicode":"\xce\xb4\xce\xb9\xce\xb1\xce\xba\xcf\x81\xce\xb9\xcf\x84\xce\xb9\xce\xba'
        b'\xce\xac \xe2\x80\x94 em\xe2\x80\x94dash \xc3\xa9\xe4\xb8\xad\xe6\x96\x87"}'
    )
    assert strict_json_parse(encoded) == tricky
