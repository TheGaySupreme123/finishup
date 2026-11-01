"""Bounded artifact facts and image parts; no rendering, OCR, URL or filesystem access."""

from __future__ import annotations

import base64
import hashlib
import re
import zlib
from typing import Final, Literal, cast

from finishup.adapters.input_summary import declared_binary_format, summarize_task_input
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

IMAGE_REVIEW_PURPOSE: Final = "semantic-review-images"
MAX_IMAGE_BYTES: Final = 4096
MAX_IMAGE_EDGE: Final = 512


def image_api(endpoint: str) -> Literal["responses", "chat", "codex"] | None:
    if endpoint in {
        "openai-responses",
        "fireworks-responses",
        "owner-declared-openai-responses",
        "vercel-ai-gateway-openai-responses",
    }:
        return "responses"
    if endpoint in {
        "anthropic-openai-chat-completions",
        "google-gemini-openai-chat-completions",
        "openrouter-openai-chat-completions",
        "xai-openai-chat-completions",
    }:
        return "chat"
    return "codex" if endpoint == "codex-chatgpt-subscription" else None


def artifact_facts(data: bytes) -> dict[str, JsonValue] | None:
    """Reuse the task-input summarizer, including its scan-before-cut and format bounds."""
    if not declared_binary_format(data):
        return None
    summary, redacted = summarize_task_input("", data, len(data))
    facts: dict[str, JsonValue] = {
        "source_digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "source_bytes": len(data),
        "method": "input-summary-v1",
        "summary": summary,
        "redacted": redacted,
        "limitation": "Header and structured facts only; no rendering, OCR or visual correctness assessment.",
    }
    first = summary.splitlines()[0]
    mime = {"format: PNG image": "image/png", "format: JPEG image": "image/jpeg"}.get(first)
    if mime is not None:
        facts["media_type"] = mime
        dimensions = re.search(r"^dimensions: ([0-9]+)x([0-9]+)$", summary, re.MULTILINE)
        if dimensions:
            facts["width"], facts["height"] = map(int, dimensions.groups())
        else:
            facts["unavailable"] = "invalid_image_header"
    return facts


def image_attachment(data: bytes, facts: dict[str, JsonValue]) -> dict[str, JsonValue] | None:
    """Whole small raster only; no cuts, re-encoding or semantic claims about the image."""

    if (
        facts.get("media_type") not in {"image/png", "image/jpeg"}
        or "unavailable" in facts
        or len(data) > MAX_IMAGE_BYTES
        or not all(
            type(facts.get(k)) is int and 0 < cast(int, facts[k]) <= MAX_IMAGE_EDGE
            for k in ("width", "height")
        )
        or not _image_structure(data, str(facts.get("media_type")))
    ):
        return None
    return {
        "media_type": facts["media_type"],
        "source_digest": facts["source_digest"],
        "content_base64": base64.b64encode(data).decode(),
    }


def _image_structure(data: bytes, media_type: str) -> bool:
    """Bounded container checks, not a pixel decoder; malformed images leave facts only."""
    if media_type == "image/png":
        pos, seen_data = 8, False
        while pos + 12 <= len(data):
            size = int.from_bytes(data[pos : pos + 4], "big")
            kind, end = data[pos + 4 : pos + 8], pos + 12 + size
            if end > len(data) or zlib.crc32(data[pos + 4 : end - 4]) != int.from_bytes(
                data[end - 4 : end], "big"
            ):
                return False
            if (pos == 8 and (kind != b"IHDR" or size != 13)) or (kind == b"IHDR" and pos != 8):
                return False
            seen_data |= kind == b"IDAT" and size > 0
            if kind == b"IEND":
                return size == 0 and seen_data and end == len(data)
            pos = end
        return False
    pos, frame, scan = 2, False, False
    while pos < len(data):
        if data[pos] != 255:
            if not scan:
                return False
            pos += 1
            continue
        while pos < len(data) and data[pos] == 255:
            pos += 1
        if pos == len(data):
            return False
        marker, pos = data[pos], pos + 1
        if marker == 217:  # EOI, outside any length-delimited segment
            return scan and pos == len(data)
        if scan and (marker == 0 or 208 <= marker <= 215):  # stuffed FF or restart
            continue
        if marker in {0, 1, 216} or 208 <= marker <= 215 or pos + 2 > len(data):
            return False
        size = int.from_bytes(data[pos : pos + 2], "big")
        if size < 2 or pos + size > len(data):
            return False
        if marker in {192, 193, 194}:  # SOF0/1/2, the header formats summarized above
            if size < 8 or not data[pos + 7] or size != 8 + 3 * data[pos + 7]:
                return False
            frame = True
        if marker == 218:  # SOS; subsequent bytes are entropy data until another marker
            if not frame or size < 6 or not data[pos + 2] or size != 6 + 2 * data[pos + 2]:
                return False
            scan = True
        pos += size
    return False


def read_image(text: str) -> tuple[dict[str, JsonValue], dict[str, JsonValue], bytes] | None:
    """Recognize a whole broker image envelope and verify its original-byte commitment."""
    try:
        envelope = strict_json_parse(text.encode())
        if not isinstance(envelope, dict) or not isinstance(envelope.get("tool_ref"), str):
            return None
        data = envelope.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("image"), dict):
            return None
        image = cast(dict[str, JsonValue], data["image"])
        encoded = image.get("content_base64")
        if type(encoded) is not str or len(encoded) > ((MAX_IMAGE_BYTES + 2) // 3) * 4:
            return None
        raw = base64.b64decode(encoded, validate=True)
        facts = artifact_facts(raw)
        if facts is None or image_attachment(raw, facts) != image:
            return None
        return envelope, image, raw
    except (ValueError, TypeError, KeyError):
        return None


def image_message(text: str, api: Literal["responses", "chat", "codex"]) -> list[JsonValue] | None:
    """Translate only a broker read's admitted image envelope, never packet or quoted text."""

    read = read_image(text)
    if read is not None:
        envelope, image, _raw = read
        data = cast(dict[str, JsonValue], envelope["data"])
        # The text descriptor and attached pixels refer to the same original bytes. Base64 is
        # transport, never presented to the model as text it should interpret or cite.
        data = {**data, "image": {k: v for k, v in image.items() if k != "content_base64"}}
        shown = canonical_encode({**envelope, "data": data}).decode()
        url = f"data:{image['media_type']};base64,{image['content_base64']}"
        if api == "responses":
            return [
                {"type": "input_text", "text": shown},
                {"type": "input_image", "image_url": url, "detail": "low"},
            ]
        if api == "chat":
            return [
                {"type": "text", "text": shown},
                {"type": "image_url", "image_url": {"url": url, "detail": "low"}},
            ]
        return [{"type": "text", "text": shown}, {"type": "image", "url": url, "detail": "low"}]
    return None


def image_messages(
    history: tuple[tuple[str, str], ...], api: Literal["responses", "chat"]
) -> list[JsonValue]:
    """Provider format, with image parsing confined to controller-owned user read turns."""
    return [
        {
            "role": role,
            "content": (image_message(text, api) if role == "user" and n > 2 else None) or text,
        }
        for n, (role, text) in enumerate(history)
    ]
