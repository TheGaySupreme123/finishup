"""#1118: the reviewer conversation's token estimate and budget.

The o200k_base counts below were measured offline with ``tiktoken`` 0.12 (``o200k_base``) on the
exact samples these deterministic generators build; FinishUP does not ship or download a
tokenizer, so the counts are recorded here rather than recomputed.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable

import pytest

from finishup.adapters.providers.codex_reviewer_catalog import (
    REVIEWER_CATALOG_MODEL,
    reviewer_model_context_window,
)
from finishup.domain.reviewer_context import (
    MAX_SIZED_EXCHANGE_BYTES,
    ReviewerContextWindow,
    estimated_model_tokens,
    reviewer_token_budget,
)


def _stream(seed: str, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{i}".encode()).digest()
        i += 1
    return bytes(out[:n])


def _code_diff() -> str:
    out: list[str] = []
    for f in range(8):
        out.append(f"diff --git a/pkg/mod{f}.py b/pkg/mod{f}.py\n")
        for line in range(400):
            out.append(
                f'+    row = {{"id": "{f}-{line}", "path": "C:\\\\data\\\\{line}", '
                f'"label": "say \\"ok\\""}}\n'
            )
    return "".join(out)


def _python_source() -> str:
    body: list[str] = []
    for i in range(600):
        body.append(
            f"def handler_{i}(request: Request, *, timeout: float = {i % 7}.5) -> Response:\n"
            f'    """Return the cached response for route {i}, refreshing it when stale."""\n'
            f"    cached = _CACHE.get(request.path)\n"
            f"    if cached is not None and cached.age < timeout:\n"
            f"        return cached.value\n"
            f"    value = fetch(request, retries={i % 3})\n"
            f"    _CACHE[request.path] = Entry(value, age=0)\n"
            f"    return value\n\n"
        )
    return "".join(body)


def _digest_json() -> str:
    rows: list[dict[str, str]] = []
    for i in range(1500):
        h = hashlib.sha256(str(i).encode()).hexdigest()
        rows.append(
            {
                "id": f"evt_{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}",
                "digest": "sha256:" + hashlib.sha256(h.encode()).hexdigest(),
            }
        )
    return json.dumps(rows)


def _tool_output() -> str:
    line = '{"level": "info", "msg": "row \\"%d\\" ok", "path": "C:\\\\run\\\\%d"}\n'
    return "".join(line % (i, n) for i in range(40) for n in range(110))


def _unicode_text() -> str:
    s = _stream("unicode", 60000)
    cjk = "".join(chr(0x4E00 + (s[k] << 4 | s[k + 1] & 15) % 0x5200) for k in range(0, 20000, 2))
    heb = "".join(chr(0x5D0 + s[k] % 27) for k in range(20000, 30000))
    emoji = "".join(chr(0x1F300 + s[k] % 0x150) for k in range(30000, 35000))
    return cjk + "\n" + heb + "\n" + emoji


def _random_base64() -> str:
    return base64.b64encode(_stream("noise", 75000)).decode()


# name -> (generator, UTF-8 bytes, o200k_base tokens)
_MEASURED: dict[str, tuple[Callable[[], str], int, int]] = {
    "code_diff": (_code_diff, 238_552, 99_312),
    "python_source": (_python_source, 222_380, 55_200),
    "digest_json": (_digest_json, 205_500, 111_363),
    "tool_output": (_tool_output, 284_900, 114_400),
    "unicode_text": (_unicode_text, 70_002, 35_663),
}


@pytest.mark.parametrize("name", sorted(_MEASURED))
def test_the_estimate_is_never_below_the_measured_o200k_count(name: str) -> None:
    generate, size, tokens = _MEASURED[name]
    text = generate().encode()
    assert len(text) == size  # the sample is the one that was measured
    estimate = estimated_model_tokens(text)
    assert estimate >= tokens
    # And not wildly above it: real content keeps most of its room.
    assert estimate <= 2.5 * tokens


def test_random_noise_is_the_documented_undercount_within_the_margin() -> None:
    text = _random_base64().encode()
    assert len(text) == 100_000
    measured = 68_264
    estimate = estimated_model_tokens(text)
    assert estimate < measured  # the one known undercount: content made of random characters
    assert estimate >= measured * 0.8


def test_non_ascii_bytes_count_one_token_each_and_ascii_five_ninths() -> None:
    assert estimated_model_tokens(b"") == 0
    assert estimated_model_tokens(b"a") == 1
    assert estimated_model_tokens(b"a" * 9) == 5
    assert estimated_model_tokens(b"a" * 10) == 6
    assert estimated_model_tokens("\u05d0".encode()) == 2
    assert estimated_model_tokens("\U0001f680".encode()) == 4
    with pytest.raises(ValueError, match="model_token_text_invalid"):
        estimated_model_tokens("text")  # type: ignore[arg-type]


def test_the_pinned_reviewer_model_budget_fits_without_compaction() -> None:
    window = reviewer_model_context_window(REVIEWER_CATALOG_MODEL)
    assert window == ReviewerContextWindow(272_000, 95)
    assert window is not None
    budget = reviewer_token_budget(window)
    # Codex compacts at 90% of the window (below its 95% usable share).
    assert budget.ceiling == 244_800
    assert budget.exchange_tokens == 244_800 - 4_096 - 40_960 - 30_600 == 169_144
    assert budget.first_exchange_tokens == 169_144 - 16_384 == 152_760
    # The hard byte bound holds every exchange the budget admits at 1.8 bytes per token, escaped
    # once more at the most escape-heavy ratio measured (1.4x).
    assert budget.exchange_tokens * 9 // 5 * 14 // 10 < MAX_SIZED_EXCHANGE_BYTES


def test_an_unpinned_model_is_not_sized() -> None:
    assert reviewer_model_context_window("gpt-unknown") is None


def test_a_window_too_small_for_the_reserves_is_refused() -> None:
    with pytest.raises(ValueError, match="reviewer_context_window_too_small"):
        reviewer_token_budget(ReviewerContextWindow(64_000, 95))
