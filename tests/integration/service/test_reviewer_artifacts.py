"""Admitted artifact reads, multimodal rendering and revocation; no network or real model."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import base64
import json
import struct
import zlib
from pathlib import Path
from typing import Any, cast

import pytest

from builders.privacy_widenings import llm_channel, with_llm
from finishup.adapters.privacy.gateway import _render_preserves_approved_case
from finishup.adapters.reviewer_artifacts import (
    IMAGE_REVIEW_PURPOSE,
    artifact_facts,
    image_attachment,
    image_message,
    read_image,
)
from finishup.application.egress import ReviewerHistory
from finishup.application.reviewer_broker import ReadRoot
from finishup.ports.semantic import ReviewerMessage, SemanticResultReply
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.models import SemanticStatus
from integration.service import test_reviewer_conversation_composition as c
from unit.adapters.providers import test_reviewer_completions as p
from unit.application import test_reviewer_loop as loop

pytestmark = pytest.mark.anyio


def _png(width: int = 2, height: int = 2, extra: bytes = b"") -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        )

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"tEXt", extra)
        + chunk(b"IDAT", zlib.compress((b"\0" + b"\xff\0\0\xff" * width) * height))
        + chunk(b"IEND", b"")
    )


def _envelope(raw: bytes) -> str:
    facts = artifact_facts(raw)
    assert facts is not None
    return canonical_encode(
        {
            "tool_ref": "sjb_1:read:1",
            "data": {
                "text": canonical_encode(facts).decode(),
                "image": image_attachment(raw, facts),
            },
        }
    ).decode()


def _image_policy() -> Any:
    return with_llm(
        c._ROOMY, allowed_purposes=(*llm_channel(c._ROOMY).allowed_purposes, IMAGE_REVIEW_PURPOSE)
    )


@pytest.mark.parametrize("permit", [False, True])
async def test_composed_review_attaches_only_with_separate_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, permit: bool
) -> None:
    raw = _png()

    def ask(case: Any, provenance: Any) -> SemanticResultReply:
        (tmp_path / "work" / "plot.png").write_bytes(raw)
        return SemanticResultReply(c._read_file("plot.png"), provenance)

    result, gateway, _ = await c._run(
        tmp_path, monkeypatch, ask, c._FINAL, policy=_image_policy() if permit else c._ROOMY
    )
    assert result.status is SemanticStatus.SUCCEEDED, (result.status, result.reason)
    message = gateway.exchanges[-1][1][-1][1]
    read = json.loads(message)
    facts = json.loads(read["data"]["text"])
    assert (facts["width"], facts["height"]) == (2, 2)
    assert facts["method"] == "input-summary-v1"
    assert (read_image(message) is not None) is permit
    assert ("image" in read["data"]) is permit
    if permit:
        assert base64.b64decode(read["data"]["image"]["content_base64"]) == raw
    assert result.reviewer is not None and result.reviewer.reads[0].result_bytes <= 8192


async def test_read_budget_drops_whole_image_and_retains_explicit_facts(tmp_path: Path) -> None:
    (tmp_path / "plot.png").write_bytes(_png(extra=b"x" * 3000))
    reviewer, broker, _, _ = loop._setup(
        loop._text("w1", "plot.png", max_bytes=2000),
        loop._FINAL,
        roots=(ReadRoot("w1", str(tmp_path.resolve())),),
        policy=_image_policy(),
    )
    broker._images = True
    (read,) = loop._observations((await reviewer.run()).history)
    assert read["status"] == "partial" and read["reason"] == "image_byte_budget"
    data, size = read["data"], read["result_utf8_bytes"]
    assert isinstance(data, dict) and "image" not in data
    text = data["text"]
    assert isinstance(text, str) and "dimensions: 2x2" in text
    assert isinstance(size, int) and size <= 2000


@pytest.mark.parametrize("blocked", ["permission", "unadmitted_bytes", "secret", "revoked"])
async def test_image_admission_scans_original_bytes_and_rechecks_permission(blocked: str) -> None:
    from finishup.protocol.models import DataCategory

    # Generated detector canary, never a credential or a new publication-scanner exception.
    raw = _png(extra=b"AWS_ACCESS_KEY_ID=AKIA" + b"Z" * 16 if blocked == "secret" else b"")
    policy = _image_policy() if blocked != "permission" else c._ROOMY
    coordinator = loop._coordinator(policy)
    binding = llm_channel(policy).provider_binding
    assert binding is not None
    elements = (
        () if blocked == "unadmitted_bytes" else ((DataCategory.REPOSITORY_EXCERPT, raw, None),)
    )
    history = ReviewerHistory()
    reason = await coordinator.admit_reviewer_read(
        "req_40000000-0000-4000-8000-000000000101",
        loop._SCOPE,
        binding,
        elements,
        _envelope(raw).encode(),
        history,
    )
    if blocked == "revoked":
        assert reason is None and history.images
        assert not history.holds(c._ROOMY, binding, loop._SCOPE.kind, ())
        assert not history.holds(policy, binding, loop._SCOPE.kind, ("/not-admitted",))
    else:
        assert reason is not None and not history.images


@pytest.mark.parametrize("route", ["responses", "chat"])
async def test_provider_body_and_sdk_carry_exact_admitted_pixels(route: str) -> None:
    text = _envelope(_png())
    history: tuple[ReviewerMessage, ...] = (
        *p._FIRST,
        ("user", "catalog"),
        ("assistant", "read the plot"),
        ("user", text),
    )
    capture = p._Capture(route)
    outcome, body, _, _ = await p._api_evaluate(route, history, capture, p._Clock())
    assert outcome.provenance.status is SemanticStatus.SUCCEEDED
    assert capture.bodies == [body]
    case = p._case(history, p._api_binding(p._api_profile(route)))
    assert _render_preserves_approved_case(case, body)
    rendered = json.loads(body)
    key = "input" if route == "responses" else "messages"
    content = rendered[key][-1]["content"]
    assert "content_base64" not in content[0]["text"]
    url = content[1].get("image_url")
    assert (url if isinstance(url, str) else url["url"]).endswith(base64.b64encode(_png()).decode())
    rendered[key][-1]["content"] = text  # Including original text cannot excuse losing pixels.
    assert not _render_preserves_approved_case(case, canonical_encode(rendered))
    rendered = json.loads(body)
    rendered[key].append({"role": "user", "content": "unapproved"})
    assert not _render_preserves_approved_case(case, canonical_encode(rendered))
    # Packet and catalog content that happens to look like a read never becomes image authority.
    assert image_message(text, "codex") is not None
    first = p._case((("system", "instruction"), ("user", text)), case.provider_binding)
    assert _render_preserves_approved_case(first, b'{"input":' + first.payload + b"}")


@pytest.mark.parametrize("vision", [True, False])
async def test_codex_continuation_checks_model_image_support(
    monkeypatch: pytest.MonkeyPatch, vision: bool
) -> None:
    from builders.codex_capability import profile_for, record_for
    from finishup.ports.semantic import ReviewerSession

    runtime = p._CodexRuntime(
        profile_for(record_for(b"c", b"h", version="0.162.1")), [p._ACTION, p._FINAL]
    )
    original = runtime.request

    async def request(*args: Any, **kwargs: Any) -> Any:
        result = cast(Any, await original(*args, **kwargs))
        if args[1] == "model/list" and vision:
            result["data"][0]["inputModalities"] = ["text", "image"]
        return result

    monkeypatch.setattr(runtime, "request", request)
    session = ReviewerSession("sjb_image", p._DEADLINE)
    cleanups: list[object] = []
    first: tuple[ReviewerMessage, ...] = (*p._FIRST, ("user", "catalog"))
    await p._codex_exchange(monkeypatch, runtime, session, first, cleanups)
    history: tuple[ReviewerMessage, ...] = (
        *first,
        ("assistant", p._ACTION),
        ("user", _envelope(_png())),
    )
    result = await p._codex_exchange(monkeypatch, runtime, session, history, cleanups)
    starts = [params for method, params in runtime.requests if method == "turn/start"]
    if vision:
        assert isinstance(result, SemanticResultReply)
        assert len(starts) == 2
        inputs = cast(list[object], starts[-1]["input"])
        assert inputs[1] == {
            "type": "image",
            "detail": "low",
            "url": "data:image/png;base64," + base64.b64encode(_png()).decode(),
        }
    else:
        assert len(starts) == 1
        assert result.provenance.runtime_evidence is not None
        assert result.provenance.runtime_evidence.failure_stage == "model_unavailable"
    await session.aclose()


def test_facts_keep_scope_and_format_limits_explicit() -> None:
    forged = json.loads(_envelope(_png()))
    forged["data"]["image"]["source_digest"] = "sha256:" + "0" * 64
    assert read_image(json.dumps(forged)) is None
    facts = artifact_facts(_png(513, 1))
    assert facts is not None and image_attachment(_png(513, 1), facts) is None
    large = _png(extra=b"x" * 4096)
    facts = artifact_facts(large)
    assert facts is not None and facts["source_bytes"] == len(large)
    assert image_attachment(large, facts) is None
    invalid = artifact_facts(b"\x89PNG\r\n\x1a\n")
    assert invalid is not None and invalid["unavailable"] == "invalid_image_header"
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><text x="1">A</text><image href="https://example.invalid/x"/></svg>'
    facts = artifact_facts(svg)
    assert facts is not None and facts["method"] == "input-summary-v1"
    assert "text: x=1; text=A" in str(facts["summary"])
    assert "example.invalid" not in json.dumps(facts)
    assert "no rendering" in str(facts["summary"])
    refused = artifact_facts(b'<!DOCTYPE svg [<!ENTITY x "a">]><svg>&x;</svg>')
    assert refused is not None and "refused XML" in str(refused["summary"])
    pdf = artifact_facts(b"%PDF-1.7\n1 0 obj <</Type /Page>> endobj")
    assert pdf is not None and "PDF document" in str(pdf["summary"])
    assert artifact_facts(b'const icon = "<svg viewBox=...>";') is None


@pytest.mark.parametrize("damage", ["truncated", "bad_crc", "oversized_chunk", "header_only"])
def test_corrupt_png_is_facts_only(damage: str) -> None:
    raw = _png(extra=b"acTL")  # A metadata substring is not an animation chunk or a refusal.
    facts = artifact_facts(raw)
    assert facts is not None and image_attachment(raw, facts) is not None
    if damage == "truncated":
        raw = raw[:-1]
    elif damage == "bad_crc":
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
    elif damage == "oversized_chunk":
        raw = raw[:33] + b"\xff\xff\xff\xff" + raw[37:]
    else:
        raw = raw[:33]
    facts = artifact_facts(raw)
    assert facts is not None and (facts["width"], facts["height"]) == (2, 2)
    assert image_attachment(raw, facts) is None


def test_jpeg_segments_and_entropy_markers_are_checked() -> None:
    # One-component SOF/SOS container with stuffed FF and restart markers in entropy data.
    frame = b"\xff\xc0\x00\x0b\x08\x00\x02\x00\x02\x01\x01\x11\x00"
    scan = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    raw = b"\xff\xd8" + frame + scan + b"\x12\xff\x00\x34\xff\xd0\x56\xff\xd9"
    facts = artifact_facts(raw)
    assert facts is not None and image_attachment(raw, facts) is not None
    for damaged in (
        raw[:-1],
        raw[:15] + b"\xff\xd9",
        raw.replace(b"\x00\x0b", b"\xff\xff"),
        raw.replace(scan, b"\xff\xda\x00\x01"),
    ):
        facts = artifact_facts(damaged)
        assert facts is not None and image_attachment(damaged, facts) is None
