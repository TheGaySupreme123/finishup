"""Image tool results become local digest-only evidence (P3-2, issue #1013).

The owner's rule: "just ack the image, don't send it". A hook that sees an image result records
the SHA-256 and byte count of the decoded image, a media type sniffed from its bytes, and the
pixel size read from the header, then drops the bytes. The service materializes one
``evidence_recorded`` 1.2.0 per image, linked from the call's result. No pixel is captured.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
import uuid
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.application.observation_materialize import materialize_observation_envelope
from finishup.cli.hook_io import (
    MAX_HOOK_STDIN_BYTES,
    MAX_OBSERVED_IMAGES,
    OBSERVED_IMAGE_MEDIA_TYPES,
    image_header_facts,
    observed_image_facts,
    read_hook_ingress,
)
from finishup.cli.observe_hooks import handle_claude_observe, handle_cursor_observe, handle_observe
from finishup.domain import observation as domain_observation
from finishup.domain.events import (
    EvidenceContentAvailability,
    EvidenceDigestProvenance,
    EvidenceDigestSubject,
    EvidenceImmutability,
    EvidenceKind,
    EvidenceRecordedPayload,
    ResultRecordedPayload,
)
from finishup.domain.observation import ObservationEnvelope
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind


def _png(width: int, height: int, *, padding: int = 0) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    rows = b"".join(b"\x00" + b"\x00\x00\x00" * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"tEXt", b"pad\x00" + b"p" * padding)
        + chunk(b"IEND", b"")
    )


def _jpeg(width: int, height: int) -> bytes:
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sof0 = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, height, width, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + app0 + sof0 + b"\xff\xda\x00\x02" + b"\x00" * 16 + b"\xff\xd9"


def _gif(width: int, height: int) -> bytes:
    return b"GIF89a" + struct.pack("<HH", width, height) + b"\x00\x00\x00;"


def _webp_vp8x(width: int, height: int) -> bytes:
    body = b"VP8X" + struct.pack("<I", 10) + b"\x00\x00\x00\x00"
    body += (width - 1).to_bytes(3, "little") + (height - 1).to_bytes(3, "little")
    return b"RIFF" + struct.pack("<I", len(body) + 4) + b"WEBP" + body


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# --- header parsing -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (_png(640, 480), ("image/png", 640, 480)),
        (_jpeg(1920, 1080), ("image/jpeg", 1920, 1080)),
        (_gif(32, 16), ("image/gif", 32, 16)),
        (_webp_vp8x(300, 200), ("image/webp", 300, 200)),
        (b"\x89PNG\r\n\x1a\n\x00\x00", ("image/unknown", None, None)),
        (b"\xff\xd8\xff\xe0\x00\x10JFIF", ("image/unknown", None, None)),
        (_png(1, 1)[:16] + b"\x00" * 8, ("image/unknown", None, None)),
        (b"BM" + b"\x00" * 64, ("image/unknown", None, None)),
    ],
    ids=["png", "jpeg", "gif", "webp", "png-short", "jpeg-no-sof", "png-zero", "bmp"],
)
def test_header_facts_are_read_from_bytes_only(
    data: bytes, expected: tuple[str, int | None, int | None]
) -> None:
    assert image_header_facts(data) == expected


def test_media_types_match_the_domain_contract() -> None:
    assert set(OBSERVED_IMAGE_MEDIA_TYPES) == domain_observation.OBSERVED_IMAGE_MEDIA_TYPES
    assert MAX_OBSERVED_IMAGES == domain_observation.MAX_OBSERVED_IMAGES


def test_the_label_never_decides_the_media_type() -> None:
    facts = observed_image_facts(
        {"content": [{"type": "image", "mimeType": "image/png", "data": _b64(_jpeg(8, 4))}]}
    )
    assert facts == [
        {
            "byte_count": len(_jpeg(8, 4)),
            "content_digest": _sha(_jpeg(8, 4)),
            "media_type": "image/jpeg",
            "width": 8,
            "height": 4,
        }
    ]


def test_a_host_value_under_the_reserved_key_is_discarded() -> None:
    forged = {"byte_count": 1, "content_digest": "sha256:" + "0" * 64, "media_type": "image/png"}
    payload, _omitted = read_hook_ingress(
        json.dumps({"tool_name": "Bash", "observed_images": [forged]}).encode()
    )
    assert "observed_images" not in payload


def test_at_most_eight_images_are_recorded() -> None:
    blocks: list[JsonValue] = [
        {"type": "input_image", "image_url": "data:image/png;base64," + _b64(_png(index + 1, 1))}
        for index in range(12)
    ]
    assert len(observed_image_facts({"tool_response": blocks})) == MAX_OBSERVED_IMAGES


# --- per host, end to end through the hook and the materializer --------------------------------


def _consented(tmp_path: Path) -> tuple[LocalObservationStore, str]:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    return store, workspace


def _codex(tmp_path: Path, call: str, response: JsonValue | None) -> None:
    for event in ("PreToolUse", "PostToolUse"):
        payload: dict[str, JsonValue] = {
            "session_id": "01a006a4-1111-4111-8111-00000000f3f2",
            "turn_id": "turn-1",
            "hook_event_name": event,
            "tool_name": "view_image",
            "tool_input": {"path": "out/render.png"},
            "tool_use_id": call,
        }
        if event == "PostToolUse" and response is not None:
            payload["tool_response"] = response
        assert (
            handle_observe(
                event_name=None,
                stdin_bytes=json.dumps(payload).encode(),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
            )
            == 0
        )


def _claude(tmp_path: Path, call: str, response: JsonValue | None) -> None:
    for event in ("PreToolUse", "PostToolUse"):
        payload: dict[str, JsonValue] = {
            "session_id": "claude-p32",
            "hook_event_name": event,
            "tool_name": "Read",
            "tool_use_id": call,
            "tool_input": {"file_path": str(tmp_path / "render.png")},
        }
        if event == "PostToolUse" and response is not None:
            payload["tool_response"] = response
        assert (
            handle_claude_observe(
                event_name=event,
                stdin_bytes=json.dumps(payload).encode(),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
                observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )


def _cursor(tmp_path: Path, call: str, response: JsonValue | None) -> None:
    for event in ("preToolUse", "postToolUse"):
        payload: dict[str, JsonValue] = {
            "conversation_id": "cursor-p32",
            "session_id": "cursor-p32",
            "hook_event_name": event,
            "tool_name": "MCP:screenshot",
            "tool_use_id": call,
            "workspace_roots": [str(tmp_path.resolve())],
        }
        if event == "postToolUse" and response is not None:
            payload["tool_output"] = response
        assert (
            handle_cursor_observe(
                event_name=event,
                stdin_bytes=json.dumps(payload).encode(),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=tmp_path,
                skip_service=True,
                observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )


def _codex_image(data: bytes) -> JsonValue:
    return [
        {"type": "input_text", "text": '{"crop":"headline"}'},
        {"type": "input_image", "image_url": "data:image/png;base64," + _b64(data)},
    ]


def _claude_image(data: bytes) -> JsonValue:
    return {"type": "image", "file": {"base64": _b64(data), "type": "image/png"}}


def _cursor_image(data: bytes) -> JsonValue:
    return {"content": [{"type": "image", "data": _b64(data), "mimeType": "image/png"}]}


_Host = Callable[[Path, str, JsonValue | None], None]
_HOSTS: list[tuple[str, _Host, Callable[[bytes], JsonValue]]] = [
    ("codex", _codex, _codex_image),
    ("claude", _claude, _claude_image),
    ("cursor", _cursor, _cursor_image),
]


def _post_envelope(store: LocalObservationStore, workspace: str) -> ObservationEnvelope:
    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 2
    return envelopes[-1]


def _image_evidence(
    envelope: ObservationEnvelope,
) -> tuple[list[EvidenceRecordedPayload], list[ResultRecordedPayload]]:
    batch = materialize_observation_envelope(
        envelope, task_id=PREFIX_BY_KIND[IdKind.TASK] + str(uuid.uuid4())
    )
    images: list[EvidenceRecordedPayload] = []
    results: list[ResultRecordedPayload] = []
    for item in batch.drafts:
        payload = item.draft.payload
        if type(payload) is EvidenceRecordedPayload and item.role.startswith("observed_image_"):
            assert item.draft.schema.version == "1.2.0"
            images.append(payload)
        elif type(payload) is ResultRecordedPayload:
            results.append(payload)
    return images, results


@pytest.mark.parametrize(("host", "run", "shape"), _HOSTS, ids=[name for name, *_ in _HOSTS])
@pytest.mark.parametrize(
    ("image", "media", "size"),
    [
        (_png(640, 360), "image/png", (640, 360)),
        (_jpeg(1024, 768), "image/jpeg", (1024, 768)),
        # Over the 1 MiB trusted cap: the skim records the same fact before dropping the bytes.
        (_png(800, 600, padding=MAX_HOOK_STDIN_BYTES), "image/png", (800, 600)),
    ],
    ids=["png", "jpeg", "png-oversize"],
)
def test_one_image_result_is_one_digest_only_evidence_row(
    tmp_path: Path,
    host: str,
    run: _Host,
    shape: Callable[[bytes], JsonValue],
    image: bytes,
    media: str,
    size: tuple[int, int],
) -> None:
    store, workspace = _consented(tmp_path)
    run(tmp_path, f"{host}-img", shape(image))
    envelope = _post_envelope(store, workspace)
    assert envelope.content_object_refs == ()
    structural = canonical_encode(envelope.structural_payload).decode()
    assert _b64(image)[:64] not in structural
    assert "observed_images" in structural

    images, results = _image_evidence(envelope)
    assert len(images) == 1
    evidence = images[0]
    assert evidence.evidence_kind is EvidenceKind.ARTIFACT
    assert evidence.strength is EvidenceImmutability.CONTENT_DIGEST
    assert evidence.captured_object_id is None
    assert evidence.content_digest == _sha(image)
    binding = evidence.digest_binding
    assert binding is not None
    assert binding.subject is EvidenceDigestSubject.ARTIFACT_BYTES
    assert binding.content_availability is EvidenceContentAvailability.DIGEST_ONLY
    assert binding.provenance is EvidenceDigestProvenance.OBSERVATION_CAPTURED
    assert binding.byte_count == len(image)
    assert evidence.description == (
        f"Observed image tool result {media} {size[0]}x{size[1]} ({len(image)} bytes); "
        "pixels were not captured or sent"
    )
    assert len(results) == 1
    assert evidence.evidence_id in results[0].evidence_refs
    # Cross-lane (L5 D6, #983): the review packet recognizes this exact row as an observed image
    # notice and a FinishUP-limit (unsupported data type) target, never a request for its pixels.
    from finishup.application.missing_for_assessment import observed_image_evidence

    assert observed_image_evidence(evidence)


@pytest.mark.parametrize(("host", "run", "shape"), _HOSTS, ids=[name for name, *_ in _HOSTS])
def test_a_non_image_result_records_no_image_evidence(
    tmp_path: Path, host: str, run: _Host, shape: Callable[[bytes], JsonValue]
) -> None:
    del shape
    store, workspace = _consented(tmp_path)
    run(tmp_path, f"{host}-text", {"content": [{"type": "text", "text": "x" * 4096}]})
    envelope = _post_envelope(store, workspace)
    assert "observed_images" not in envelope.structural_payload
    images, _results = _image_evidence(envelope)
    assert images == []


@pytest.mark.parametrize(("host", "run", "shape"), _HOSTS, ids=[name for name, *_ in _HOSTS])
def test_a_malformed_header_is_image_unknown_without_dimensions(
    tmp_path: Path, host: str, run: _Host, shape: Callable[[bytes], JsonValue]
) -> None:
    store, workspace = _consented(tmp_path)
    broken = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
    run(tmp_path, f"{host}-broken", shape(broken))
    images, _results = _image_evidence(_post_envelope(store, workspace))
    assert len(images) == 1
    assert images[0].description == (
        f"Observed image tool result image/unknown ({len(broken)} bytes); "
        "pixels were not captured or sent"
    )
    assert images[0].content_digest == _sha(broken)


def test_the_image_fact_survives_the_wire_round_trip(tmp_path: Path) -> None:
    from finishup.domain.observation import (
        observation_envelope_from_json,
        observation_envelope_to_json,
    )

    store, workspace = _consented(tmp_path)
    _codex(tmp_path, "codex-wire", _codex_image(_png(4, 4)))
    envelope = _post_envelope(store, workspace)
    wire = observation_envelope_to_json(envelope)
    assert observation_envelope_from_json(wire) == envelope
