"""Oversized hook bodies keep their structural row on every host (tb4n1 B5, issue #667).

tb4n1 lost 96 PostToolUse rows to the old 256 KiB ingress cap: 42 were Yoetz's own
``closure_prepare`` replies (300 KB-1 MB), most of the rest image views (``view_image`` data URLs)
and large ``cat`` outputs. Each loss left its pre-event unpaired. These tests pin the fix: a larger
trusted cap, a skim up to ``MAX_HOOK_SKIM_BYTES`` for Codex and Claude Code as well as Cursor,
image bytes dropped instead of the event, and no coverage gap for Yoetz's own tools.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.cli import hook_io
from yoetz.cli.hook_io import (
    MAX_HOOK_SKIM_BYTES,
    MAX_HOOK_STDIN_BYTES,
    OversizedHookPayloadError,
    read_cursor_hook_ingress,
    read_hook_ingress,
    strip_hook_media,
)
from yoetz.cli.observe_hooks import (
    handle_claude_observe,
    handle_cursor_observe,
    handle_observe,
    handle_spool,
    yoetz_mcp_tool,
)
from yoetz.domain.observation import ObservationGapCode, ObservationStatusQuery
from yoetz.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.errors import ProtocolValueError

_CONTENT_OMITTED = ObservationGapCode.PAYLOAD_CONTENT_OMITTED.value
_TOO_LARGE = ObservationGapCode.PAYLOAD_TOO_LARGE.value
_UNPAIRED = ObservationGapCode.UNPAIRED_EVENT.value
_CANARY = "SECRET_CONTENT_CANARY"
# The tb4n1 cumulative-layout-shift D closure_prepare replies were 905-999 KB.
_CLOSURE_PREPARE_BYTES = 900_000


def _closure_prepare_response(size: int) -> dict[str, JsonValue]:
    """An MCP CallToolResult shaped like a large ``closure_prepare`` inventory reply."""

    return {
        "content": [{"type": "text", "text": _CANARY + "r" * size}],
        "structuredContent": {"ok": True, "inventory": {"results": [{"summary": _CANARY}]}},
        "isError": False,
    }


def _data_url(size: int) -> str:
    return "data:image/png;base64," + "iVBORw0KGgo" * (size // 11)


def _image_response(size: int) -> list[JsonValue]:
    """Codex's view_image / code-mode output: text items beside ``input_image`` data URLs."""

    return [
        {"type": "input_text", "text": '{"crop":"headline"}'},
        {"type": "input_image", "image_url": _data_url(size // 2), "detail": "high"},
        {"type": "input_image", "image_url": _data_url(size // 2), "detail": "high"},
    ]


def _consented(tmp_path: Path) -> tuple[LocalObservationStore, str]:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    return store, workspace


def _diagnostic_reasons(state: Path) -> list[str]:
    path = state / "observation/hook-diagnostics.jsonl"
    if not path.exists():
        return []
    return [
        cast(str, json.loads(line)["reason"])
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def _encoded(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode()


# --- hook_io ------------------------------------------------------------------------------------


def test_trusted_cap_is_one_mib_and_the_skim_reaches_eight() -> None:
    assert MAX_HOOK_STDIN_BYTES == 1_048_576
    assert MAX_HOOK_SKIM_BYTES == 8 * 1_048_576


def test_a_closure_prepare_sized_body_is_now_a_full_parse() -> None:
    body = _encoded(
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "mcp__yoetz__closure_prepare",
            "tool_response": cast(JsonValue, _closure_prepare_response(_CLOSURE_PREPARE_BYTES)),
        }
    )
    assert 262_144 < len(body) <= MAX_HOOK_STDIN_BYTES
    payload, omitted = read_hook_ingress(body)
    assert omitted is False
    assert _CANARY in json.dumps(payload)


def test_an_oversized_body_keeps_only_closed_identity() -> None:
    body = _encoded(
        {
            "session_id": "codex-s",
            "turn_id": "turn-9",
            "transcript_path": "/w/.codex/sessions/rollout.jsonl",
            "cwd": "/w/project",
            "hook_event_name": "PostToolUse",
            "tool_name": "exec_command",
            "tool_use_id": "call_9",
            "tool_input": {"cmd": f"cat {_CANARY}.csv", "workdir": "/w/project"},
            "tool_response": {"output": _CANARY + "x" * (2 * MAX_HOOK_STDIN_BYTES), "ratio": 0.5},
        }
    )
    payload, omitted = read_hook_ingress(body)
    assert omitted is True
    assert payload["session_id"] == "codex-s"
    assert payload["turn_id"] == "turn-9"
    assert payload["transcript_path"] == "/w/.codex/sessions/rollout.jsonl"
    assert payload["tool_name"] == "exec_command"
    assert payload["tool_use_id"] == "call_9"
    assert _CANARY not in json.dumps(payload)
    assert "tool_response" not in payload


def test_image_bytes_are_dropped_and_the_event_is_kept_whole() -> None:
    body = _encoded(
        {
            "session_id": "codex-s",
            "hook_event_name": "PostToolUse",
            "tool_name": "view_image",
            "tool_use_id": "call_img",
            "tool_response": _image_response(3 * MAX_HOOK_STDIN_BYTES),
        }
    )
    assert MAX_HOOK_STDIN_BYTES < len(body) <= MAX_HOOK_SKIM_BYTES
    payload, omitted = read_hook_ingress(body)
    assert omitted is False
    response = cast(list[dict[str, JsonValue]], payload["tool_response"])
    assert response[0] == {"type": "input_text", "text": '{"crop":"headline"}'}
    assert response[1]["image_url"] == "[media bytes omitted by Yoetz]"
    assert response[1]["detail"] == "high"
    assert "iVBOR" not in json.dumps(payload)


def test_the_skim_refuses_past_its_cap_and_names_unsafe_complete_bodies() -> None:
    with pytest.raises(ProtocolValueError) as over:
        read_hook_ingress(b"\x00" + b"x" * MAX_HOOK_SKIM_BYTES)
    assert over.value.reason_code == "payload_too_large"
    duplicate = b'{"a":1,"a":2,"pad":"' + b"x" * MAX_HOOK_STDIN_BYTES + b'"}'
    with pytest.raises(OversizedHookPayloadError) as unsafe:
        read_hook_ingress(duplicate)
    assert unsafe.value.reason_code == "duplicate_object_key"
    # Inside the trusted cap the reader is exactly the strict parser.
    with pytest.raises(ProtocolValueError) as strict:
        read_hook_ingress(b'{"ratio":0.5}')
    assert strict.value.reason_code == "float_forbidden"


@pytest.mark.parametrize(
    "body",
    [
        b"[" + b"{}," * (3 * MAX_HOOK_STDIN_BYTES // 3) + b"{}]",
        b"[" + b"1," * (2 * MAX_HOOK_STDIN_BYTES) + b"1]",
        b'{"tool_response":[' + b"[]," * MAX_HOOK_STDIN_BYTES + b"[]]}",
    ],
    ids=["empty-objects", "integers", "nested-arrays"],
)
@pytest.mark.parametrize("reader", [read_hook_ingress, read_cursor_hook_ingress])
def test_a_structure_heavy_oversized_body_is_refused_before_any_parse(
    body: bytes,
    reader: Callable[[bytes], object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Adversarial review (tb4n1 B5): an 8 MiB `[{},...]` took 12.6 s and 418 MB to skim. The
    # budget is a count of structural tokens, so the refusal is proven by the parser never
    # running, not by a clock.
    def no_parse(_data: bytes) -> object:
        raise AssertionError("the skim parsed a structure-heavy body")

    monkeypatch.setattr(hook_io, "_parse_cursor_hook_document", no_parse)
    assert MAX_HOOK_STDIN_BYTES < len(body) <= MAX_HOOK_SKIM_BYTES
    with pytest.raises(ProtocolValueError) as refused:
        reader(body)
    assert refused.value.reason_code == "payload_too_large"


def test_structure_inside_strings_does_not_spend_the_budget() -> None:
    text = '{"a":[1,2,3]},' * (MAX_HOOK_STDIN_BYTES // 8)
    body = _encoded({"session_id": "s", "tool_name": "Bash", "tool_response": {"stdout": text}})
    assert MAX_HOOK_STDIN_BYTES < len(body) <= MAX_HOOK_SKIM_BYTES
    payload, omitted = read_hook_ingress(body)
    assert omitted is True
    assert payload["tool_name"] == "Bash"


def test_a_closure_prepare_dense_body_still_fits_the_budget() -> None:
    # tb4n1 replies carried about 30 structural tokens per KB; 4 MB of that density passes.
    rows = [{"id": f"r{index}", "ok": True, "refs": ["a", "b"]} for index in range(30_000)]
    body = _encoded(
        {
            "session_id": "s",
            "tool_name": "mcp__yoetz__closure_prepare",
            "tool_response": {
                "structuredContent": {"rows": rows},
                "pad": "p" * MAX_HOOK_STDIN_BYTES,
            },
        }
    )
    payload, omitted = read_hook_ingress(body)
    assert omitted is True
    assert payload["tool_name"] == "mcp__yoetz__closure_prepare"


def test_codex_structure_heavy_body_records_the_size_loss(tmp_path: Path) -> None:
    store, workspace = _consented(tmp_path)
    body = (
        b'{"session_id":"s","tool_name":"x","tool_response":['
        + b"{}," * MAX_HOOK_STDIN_BYTES
        + b"{}]}"
    )
    assert (
        handle_observe(
            event_name="PostToolUse",
            stdin_bytes=body,
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )
    assert _diagnostic_reasons(tmp_path) == ["codex_payload_too_large"]
    assert _TOO_LARGE in store.status(ObservationStatusQuery(workspace)).gaps
    assert store.list_envelopes(workspace) == ()


@pytest.mark.parametrize(
    "block",
    [
        {"type": "image", "data": "A" * 4096, "mimeType": "image/png"},
        {
            "type": "image",
            "source": {"type": "base64", "media_type": "image/png", "data": "A" * 4096},
        },
        {"type": "image", "file": {"base64": "A" * 4096, "type": "image/png", "originalSize": 9}},
        {"type": "input_image", "image_url": "data:image/jpeg;base64," + "A" * 4096},
        {"kind": "blob", "mime_type": "audio/wav", "bytes": "A" * 4096},
        {"type": "input_text", "text": "see data:image/png;base64," + "A" * 4096},
    ],
)
def test_strip_hook_media_covers_each_host_image_shape(block: dict[str, JsonValue]) -> None:
    stripped, omitted = strip_hook_media({"tool_response": {"content": [block]}})
    text = json.dumps(stripped)
    if block.get("type") == "input_text":
        # Text that merely mentions a data URL is text; only a data-URL value is media.
        assert omitted == 0
        assert stripped == {"tool_response": {"content": [block]}}
        return
    assert omitted >= 1
    assert "A" * 300 not in text
    assert "[media bytes omitted by Yoetz]" in text


def test_strip_hook_media_leaves_text_and_small_values_untouched() -> None:
    payload: dict[str, JsonValue] = {
        "tool_response": {
            "content": [
                {"type": "text", "text": "Z" * 10_000},
                {"type": "image", "data": "tiny", "mimeType": "image/png"},
            ]
        }
    }
    stripped, omitted = strip_hook_media(payload)
    assert omitted == 0
    assert stripped is payload


def test_cursor_skim_also_drops_image_bytes_first() -> None:
    body = _encoded(
        {
            "hook_event_name": "postToolUse",
            "conversation_id": "c",
            "tool_name": "MCP:screenshot",
            "tool_output": {
                "content": [{"type": "image", "data": "Q" * (2 * MAX_HOOK_STDIN_BYTES)}]
            },
        }
    )
    payload, omitted = read_cursor_hook_ingress(body)
    assert omitted is False
    assert "QQQQ" not in json.dumps(payload)


@pytest.mark.parametrize(
    "name",
    [
        "mcp__yoetz__closure_prepare",
        "mcp__plugin_yoetz_yoetz__closure_prepare",
        "yoetz:closure_prepare",
        "plugin-yoetz-yoetz:closure_prepare",
        "mcp__yoetz__status",
        "mcp__plugin_yoetz_yoetz__check",
    ],
)
def test_every_yoetz_mcp_spelling_is_owned(name: str) -> None:
    assert yoetz_mcp_tool(name)


@pytest.mark.parametrize("name", ["MCP:closure_prepare", "mcp__other__closure", "Bash", None, 3])
def test_unowned_or_unattributable_names_are_not(name: object) -> None:
    assert not yoetz_mcp_tool(name)


# --- Codex --------------------------------------------------------------------------------------


def _codex(event: str, call: str, **extra: JsonValue) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {
        "session_id": "01a006a4-1111-4111-8111-00000000b005",
        "turn_id": "turn-1",
        "transcript_path": "/workspace/.codex/sessions/rollout-b5.jsonl",
        "cwd": "/workspace/project",
        "hook_event_name": event,
        "model": "gpt-5.3-codex",
        "tool_name": "mcp__yoetz__closure_prepare",
        "tool_input": {"selection": {"phase": "inventory"}},
        "tool_use_id": call,
    }
    payload.update(extra)
    return payload


def _codex_pass(tmp_path: Path, payload: dict[str, JsonValue]) -> None:
    assert (
        handle_observe(
            event_name=None,
            stdin_bytes=_encoded(payload),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
        )
        == 0
    )


@pytest.mark.parametrize("size", [_CLOSURE_PREPARE_BYTES, 2 * MAX_HOOK_STDIN_BYTES])
def test_codex_closure_prepare_reply_keeps_its_row_without_a_gap(tmp_path: Path, size: int) -> None:
    store, workspace = _consented(tmp_path)
    _codex_pass(tmp_path, _codex("PreToolUse", "call_cp"))
    _codex_pass(
        tmp_path,
        _codex(
            "PostToolUse",
            "call_cp",
            tool_response=cast(JsonValue, _closure_prepare_response(size)),
        ),
    )

    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 2
    for envelope in envelopes:
        assert _UNPAIRED not in envelope.gap_codes
        assert _CONTENT_OMITTED not in envelope.gap_codes
        assert _CANARY not in json.dumps(dict(envelope.structural_payload))
    status = store.status(ObservationStatusQuery(workspace))
    assert _TOO_LARGE not in status.gaps
    assert _UNPAIRED not in status.gaps
    assert not any("payload" in reason for reason in _diagnostic_reasons(tmp_path))


def test_codex_image_view_over_the_cap_keeps_its_row_and_drops_the_bytes(tmp_path: Path) -> None:
    store, workspace = _consented(tmp_path)
    _codex_pass(tmp_path, _codex("PreToolUse", "call_img", tool_name="view_image"))
    _codex_pass(
        tmp_path,
        _codex(
            "PostToolUse",
            "call_img",
            tool_name="view_image",
            tool_response=_image_response(3 * MAX_HOOK_STDIN_BYTES),
        ),
    )
    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 2
    assert all(_UNPAIRED not in envelope.gap_codes for envelope in envelopes)
    assert all(_CONTENT_OMITTED not in envelope.gap_codes for envelope in envelopes)
    assert _TOO_LARGE not in store.status(ObservationStatusQuery(workspace)).gaps


def test_codex_large_ordinary_output_keeps_a_row_with_content_omitted(tmp_path: Path) -> None:
    store, workspace = _consented(tmp_path)
    shell: dict[str, JsonValue] = {
        "tool_name": "exec_command",
        "tool_input": {"cmd": "cat big.csv"},
    }
    _codex_pass(tmp_path, _codex("PreToolUse", "call_cat", **shell))
    _codex_pass(
        tmp_path,
        _codex(
            "PostToolUse",
            "call_cat",
            **shell,
            tool_response=_CANARY + "y" * (2 * MAX_HOOK_STDIN_BYTES),
        ),
    )
    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 2
    pre, post = envelopes
    assert _UNPAIRED not in pre.gap_codes and _UNPAIRED not in post.gap_codes
    assert _CONTENT_OMITTED in post.gap_codes
    assert _CANARY not in json.dumps(dict(post.structural_payload))
    assert _diagnostic_reasons(tmp_path) == ["codex_payload_content_omitted"]
    # A row was kept, so this is not the no-row size loss.
    assert _TOO_LARGE not in store.status(ObservationStatusQuery(workspace)).gaps


def test_legacy_codex_spool_keeps_an_oversized_closure_prepare_record(tmp_path: Path) -> None:
    _consented(tmp_path)
    body = _encoded(
        _codex(
            "PostToolUse",
            "call_spool",
            tool_response=cast(JsonValue, _closure_prepare_response(2 * MAX_HOOK_STDIN_BYTES)),
        )
    )
    assert (
        handle_spool(
            event_name="PostToolUse",
            stdin_bytes=body,
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )
    spooled = b"".join(path.read_bytes() for path in (tmp_path / "hook-spool").glob("*.jsonl"))
    assert b"call_spool" in spooled
    assert _CANARY.encode() not in spooled
    assert _diagnostic_reasons(tmp_path) == []


# --- Claude Code --------------------------------------------------------------------------------


def _claude_pass(tmp_path: Path, event: str, payload: dict[str, JsonValue]) -> None:
    assert (
        handle_claude_observe(
            event_name=event,
            stdin_bytes=_encoded({**payload, "hook_event_name": event}),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
            observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        == 0
    )


@pytest.mark.parametrize("size", [_CLOSURE_PREPARE_BYTES, 2 * MAX_HOOK_STDIN_BYTES])
def test_claude_closure_prepare_reply_keeps_its_row_without_a_gap(
    tmp_path: Path, size: int
) -> None:
    store, workspace = _consented(tmp_path)
    common: dict[str, JsonValue] = {
        "session_id": "claude-b5",
        "tool_name": "mcp__plugin_yoetz_yoetz__closure_prepare",
        "tool_use_id": "toolu_cp",
        "tool_input": {"selection": {"phase": "inventory"}},
    }
    _claude_pass(tmp_path, "PreToolUse", common)
    _claude_pass(
        tmp_path,
        "PostToolUse",
        {**common, "tool_response": cast(JsonValue, _closure_prepare_response(size))},
    )
    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 2
    for envelope in envelopes:
        assert _UNPAIRED not in envelope.gap_codes
        assert _CONTENT_OMITTED not in envelope.gap_codes
    assert _TOO_LARGE not in store.status(ObservationStatusQuery(workspace)).gaps
    assert not any("payload" in reason for reason in _diagnostic_reasons(tmp_path))


def test_claude_image_read_over_the_cap_keeps_its_row(tmp_path: Path) -> None:
    store, workspace = _consented(tmp_path)
    common: dict[str, JsonValue] = {
        "session_id": "claude-b5-img",
        "tool_name": "Read",
        "tool_use_id": "toolu_img",
        "tool_input": {"file_path": str(tmp_path / "shot.png")},
    }
    _claude_pass(tmp_path, "PreToolUse", common)
    _claude_pass(
        tmp_path,
        "PostToolUse",
        {
            **common,
            "tool_response": {
                "type": "image",
                "file": {"base64": "A" * (2 * MAX_HOOK_STDIN_BYTES), "type": "image/png"},
            },
        },
    )
    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 2
    assert all(_CONTENT_OMITTED not in envelope.gap_codes for envelope in envelopes)
    assert all(_UNPAIRED not in envelope.gap_codes for envelope in envelopes)


def test_claude_large_ordinary_output_keeps_a_row_with_content_omitted(tmp_path: Path) -> None:
    store, workspace = _consented(tmp_path)
    common: dict[str, JsonValue] = {
        "session_id": "claude-b5-cat",
        "tool_name": "Bash",
        "tool_use_id": "toolu_cat",
        "tool_input": {"command": "cat big.csv"},
    }
    _claude_pass(tmp_path, "PreToolUse", common)
    _claude_pass(
        tmp_path,
        "PostToolUse",
        {
            **common,
            "tool_response": {
                "stdout": _CANARY + "y" * (2 * MAX_HOOK_STDIN_BYTES),
                "stderr": "",
                "interrupted": False,
            },
        },
    )
    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 2
    post = envelopes[-1]
    assert _CONTENT_OMITTED in post.gap_codes
    assert _UNPAIRED not in post.gap_codes
    assert _CANARY not in json.dumps(dict(post.structural_payload))
    assert _diagnostic_reasons(tmp_path) == ["claude_payload_content_omitted"]


# --- Cursor -------------------------------------------------------------------------------------


def _cursor_pass(tmp_path: Path, event: str, payload: dict[str, JsonValue]) -> None:
    assert (
        handle_cursor_observe(
            event_name=event,
            stdin_bytes=_encoded(
                {
                    **payload,
                    "hook_event_name": event,
                    "workspace_roots": [str(tmp_path.resolve())],
                }
            ),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
            skip_service=True,
            observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        == 0
    )


@pytest.mark.parametrize(
    ("tool_name", "size", "gap"),
    [
        ("yoetz:closure_prepare", _CLOSURE_PREPARE_BYTES, False),
        ("plugin-yoetz-yoetz:closure_prepare", 2 * MAX_HOOK_STDIN_BYTES, False),
        # Cursor's generic spelling names no server, so Yoetz cannot claim the call.
        ("MCP:closure_prepare", 2 * MAX_HOOK_STDIN_BYTES, True),
    ],
)
def test_cursor_closure_prepare_reply_keeps_its_row(
    tmp_path: Path, tool_name: str, size: int, gap: bool
) -> None:
    store, workspace = _consented(tmp_path)
    common: dict[str, JsonValue] = {
        "conversation_id": "cursor-b5",
        "session_id": "cursor-b5",
        "tool_name": tool_name,
        "tool_use_id": "cursor-cp",
        "tool_input": {"selection": {"phase": "inventory"}},
    }
    _cursor_pass(tmp_path, "preToolUse", common)
    _cursor_pass(
        tmp_path,
        "postToolUse",
        {**common, "tool_output": cast(JsonValue, _closure_prepare_response(size))},
    )
    envelopes = store.list_envelopes(workspace)
    assert len(envelopes) == 2
    post = envelopes[-1]
    assert _UNPAIRED not in post.gap_codes
    assert (_CONTENT_OMITTED in post.gap_codes) is gap
    assert ("cursor_payload_content_omitted" in _diagnostic_reasons(tmp_path)) is gap
    assert _TOO_LARGE not in store.status(ObservationStatusQuery(workspace)).gaps


def test_hook_io_stays_a_leaf_module() -> None:
    # The skim must not pull the service client or schema graph into every hook (#242).
    modules = {
        module
        for value in vars(hook_io).values()
        if isinstance(module := getattr(value, "__module__", None), str)
        and module.startswith("yoetz.")
    }
    assert all(
        module == "yoetz.cli.hook_io" or module.startswith("yoetz.protocol") for module in modules
    )


def test_an_unterminated_string_is_consumed_in_one_match() -> None:
    """Review of #999: a malformed body must not restart the string match at every quote.

    One match to the end of input keeps the pre-check linear (the old pattern took ~21 s on
    80 KB of escaped quotes); the parse then refuses the body.
    """

    from yoetz.cli.hook_io import _JSON_STRING_TOKEN  # pyright: ignore[reportPrivateUsage]

    body = b'{"a": 1, "b": "' + b'\\"' * 50_000
    assert _JSON_STRING_TOKEN.sub(b'""', body) == b'{"": 1, "": ""'
    assert len(_JSON_STRING_TOKEN.findall(b'"' + b'\\"' * 50_000)) == 1
