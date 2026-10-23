"""Bounded artifact facts and image parts; no rendering, OCR, URL or filesystem access."""

from __future__ import annotations

import base64
import hashlib
import re
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
    ):
        return None
    return {
        "media_type": facts["media_type"],
        "source_digest": facts["source_digest"],
        "content_base64": base64.b64encode(data).decode(),
    }


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
