"""Event-specific Codex hook stdout contracts (#222)."""

from __future__ import annotations

import io
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from yoetz.cli import hook_io as hook_io_module
from yoetz.cli.hook_io import (
    MAX_HOOK_SKIM_BYTES,
    MAX_HOOK_STDIN_BYTES,
    CursorOversizedPayloadError,
    claude_context_output,
    context_output,
    cursor_context_output,
    read_cursor_hook_ingress,
    read_cursor_hook_payload,
    read_hook_payload,
    stdout_json,
)
from yoetz.protocol.canonical import strict_json_parse
from yoetz.protocol.errors import ProtocolValueError


def test_session_start_and_post_tool_use_emit_additional_context() -> None:
    for event in ("SessionStart", "PostToolUse", "UserPromptSubmit"):
        assert context_output(event, "  bounded advice  ") == {
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": "bounded advice",
            }
        }


def test_stop_and_subagent_stop_emit_block_decision_not_hook_specific_output() -> None:
    for event in ("Stop", "SubagentStop"):
        emitted = context_output(event, "refresh status before an exact-frontier check")
        assert emitted == {
            "decision": "block",
            "reason": "refresh status before an exact-frontier check",
        }
        assert "hookSpecificOutput" not in emitted


def test_session_end_and_unknown_events_emit_empty_object() -> None:
    assert context_output("SessionEnd", "would be discarded by the host") == {}
    assert context_output("PreCompact", "never an advice channel") == {}
    assert context_output("Stop", "   ") == {}
    assert context_output("SessionStart", "") == {}


def test_cursor_session_start_emits_cursor_native_additional_context() -> None:
    assert cursor_context_output("sessionStart", "  bounded advice  ") == {
        "additional_context": "bounded advice"
    }


def test_cursor_post_tool_use_emits_cursor_native_additional_context() -> None:
    assert cursor_context_output("postToolUse", "  bounded advice  ") == {
        "additional_context": "bounded advice"
    }


def test_cursor_stop_does_not_auto_submit_a_followup_message() -> None:
    assert cursor_context_output("stop", "submit this as a new user message") == {}


def test_cursor_stop_followup_is_explicitly_opt_in() -> None:
    assert cursor_context_output(
        "stop", "  submit this as a new user message  ", allow_stop_followup=True
    ) == {"followup_message": "submit this as a new user message"}


def test_cursor_outputless_and_unknown_events_emit_empty_object() -> None:
    for event in (
        "postToolUseFailure",
        "afterFileEdit",
        "afterMCPExecution",
        "sessionEnd",
        "unknown",
    ):
        assert cursor_context_output(event, "advice that has no output channel") == {}


def test_cursor_context_is_bounded_and_a_cut_ends_with_a_visible_marker() -> None:
    """Yoetz's own 2,000-character cap (not a documented host limit); a cut says so (tb4n3)."""

    advice = "x" * 2_001
    for event in ("sessionStart", "postToolUse"):
        delivered = cursor_context_output(event, advice)["additional_context"]
        assert isinstance(delivered, str)
        assert len(delivered) == 2_000
        assert delivered.endswith("[Yoetz text cut at 2000 characters; read status or the receipt]")
        assert delivered.startswith("x" * 100)
    exact = "y" * 2_000
    assert cursor_context_output("sessionStart", exact) == {"additional_context": exact}


def test_cursor_post_tool_use_stdout_is_canonical_and_bounded() -> None:
    stream = io.BytesIO()
    assert stdout_json(cursor_context_output("postToolUse", "  bounded advice  "), stream)
    assert stream.getvalue() == b'{"additional_context":"bounded advice"}\n'


def test_codex_context_output_keeps_canonical_stdout_bytes() -> None:
    stream = io.BytesIO()
    assert stdout_json(context_output("SessionStart", "bounded advice"), stream)
    assert (
        stream.getvalue() == b'{"hookSpecificOutput":{"additionalContext":"bounded advice",'
        b'"hookEventName":"SessionStart"}}\n'
    )


def test_claude_stop_emits_documented_non_error_additional_context() -> None:
    """Claude Code documents Stop/SubagentStop additionalContext as non-error feedback (#420)."""

    for event in ("Stop", "SubagentStop"):
        emitted = claude_context_output(event, "  refresh status before an exact-frontier check  ")
        assert emitted == {
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": "refresh status before an exact-frontier check",
            }
        }
        assert "decision" not in emitted


def test_claude_context_matches_codex_on_shared_additional_context_events() -> None:
    for event in ("SessionStart", "PostToolUse", "UserPromptSubmit", "PreToolUse", "SubagentStart"):
        assert claude_context_output(event, "bounded advice") == context_output(
            event, "bounded advice"
        )


def test_claude_post_tool_failure_preserves_its_host_event_name() -> None:
    assert claude_context_output("PostToolUseFailure", "bounded advice") == {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUseFailure",
            "additionalContext": "bounded advice",
        }
    }


def test_claude_session_end_blank_and_unknown_events_emit_empty_object() -> None:
    assert claude_context_output("SessionEnd", "would be discarded by the host") == {}
    assert claude_context_output("PreCompact", "never an advice channel") == {}
    assert claude_context_output("Stop", "   ") == {}
    assert claude_context_output("SessionStart", "") == {}


def test_claude_context_is_bounded_by_the_shared_context_limit() -> None:
    delivered = claude_context_output("Stop", "x" * 2_001)["hookSpecificOutput"]
    assert isinstance(delivered, dict)
    text = delivered["additionalContext"]
    assert isinstance(text, str) and len(text) == 2_000
    assert text.endswith("[Yoetz text cut at 2000 characters; read status or the receipt]")


@pytest.mark.parametrize("host", ("codex", "claude", "cursor"))
def test_truncated_bootstrap_keeps_the_current_procedure_route(host: str) -> None:
    """Exercise delivered hook payloads; full source presence misses the truncation bug."""
    root = Path(__file__).resolve().parents[3]
    instructions = (root / "guidance/agent-instructions.md").read_text(encoding="utf-8")
    if host == "cursor":
        rendered = cursor_context_output("sessionStart", instructions)
        delivered = rendered["additional_context"]
    else:
        render = claude_context_output if host == "claude" else context_output
        rendered = render("SessionStart", instructions)
        specific = rendered["hookSpecificOutput"]
        assert isinstance(specific, dict)
        delivered = specific["additionalContext"]
    assert isinstance(delivered, str)
    assert len(delivered) <= 2_000
    assert len(delivered) < len(instructions)
    assert "yoetz://guidance/workflow.md" in delivered
    assert "current" in delivered.lower()
    assert "memory" in delivered.lower()


def test_intake_cue_keeps_a_complete_workflow_uri_before_the_byte_limit() -> None:
    from yoetz.cli.hooks import intake_cue_text

    root = Path(__file__).resolve().parents[3]
    cue = intake_cue_text(resource_root=root)
    assert len(cue.encode("utf-8")) <= 512
    assert "yoetz://guidance/workflow.md" in cue
    assert "start" in cue
    assert "material" in cue


@pytest.mark.parametrize(
    ("literal", "expected"),
    [("428.607", 428), ("428.5", 428), ("428.499", 428), ("0.0", 0), ("1e3", 1_000)],
)
def test_cursor_hook_payload_truncates_fractional_duration_to_canonical_integer(
    literal: str, expected: int
) -> None:
    payload = ('{"duration":' + literal + ',"hook_event_name":"afterMCPExecution"}').encode()

    parsed = read_cursor_hook_payload(payload)

    assert parsed["duration"] == expected
    # The canonical parser remains float-free for every non-Cursor wire surface.
    with pytest.raises(ProtocolValueError, match="float_forbidden"):
        strict_json_parse(payload)


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b'{"duration":-1.0}', "invalid_duration"),
        (b'{"duration":NaN}', "float_forbidden"),
        (b'{"duration":1.2,"duration":2.3}', "duplicate_object_key"),
        (b'{"duration":9007199254740992}', "integer_out_of_safe_range"),
        (b'{"duration":9007199254740991.4}', "integer_out_of_safe_range"),
        (b'{"value":"\\u0000"}', "nul_byte_forbidden"),
    ],
)
def test_cursor_hook_payload_preserves_bounded_wire_rejections(payload: bytes, reason: str) -> None:
    with pytest.raises(ProtocolValueError, match=reason):
        read_cursor_hook_payload(payload)


def test_cursor_hook_payload_discards_nested_vendor_floats() -> None:
    parsed = read_cursor_hook_payload(
        b'{"model_params":[{"id":"temperature","value":0.2}],'
        b'"tool_input":{"ratio":1.5},"hook_event_name":"afterMCPExecution"}'
    )

    assert parsed["model_params"] == [{"id": "temperature", "value": None}]
    assert parsed["tool_input"] == {"ratio": None}


def _at_cap_payload() -> bytes:
    """Return a valid hook object whose encoded length is exactly the cap."""

    prefix = b'{"hook_event_name":"PostToolUse","pad":"'
    suffix = b'"}'
    return prefix + b"x" * (MAX_HOOK_STDIN_BYTES - len(prefix) - len(suffix)) + suffix


@pytest.mark.parametrize("reader", [read_hook_payload, read_cursor_hook_payload])
def test_hook_ingress_admits_the_exact_cap_and_names_only_the_byte_bound_above_it(
    reader: Callable[[bytes], Mapping[str, object]],
) -> None:
    admitted = _at_cap_payload()
    assert len(admitted) == MAX_HOOK_STDIN_BYTES
    assert reader(admitted)["hook_event_name"] == "PostToolUse"

    with pytest.raises(ProtocolValueError) as oversized:
        reader(admitted[:-1] + b'x"}')

    # An ordinary edit that outgrew the cap and a host that sent nothing shared
    # one reason, so neither the operator nor the observation ingress could tell
    # a size refusal from a malformed envelope (issue #667).
    assert oversized.value.reason_code == "payload_too_large"

    with pytest.raises(ProtocolValueError) as empty:
        reader(b"")

    assert empty.value.reason_code == "invalid_event_value_type"

    with pytest.raises(ProtocolValueError) as malformed:
        reader(b'{"hook_event_name":')

    assert malformed.value.reason_code == "malformed_json"


def test_oversize_refusal_precedes_every_body_inspecting_rejection() -> None:
    # The size branch runs before the NUL scan, the UTF-8 decode and the parse,
    # so an oversized body is named for its size even when its bytes would also
    # have failed one of those checks.
    unsafe = b'{"value":"\x00' + b"x" * MAX_HOOK_STDIN_BYTES + b'"}'

    for reader in (read_hook_payload, read_cursor_hook_payload):
        with pytest.raises(ProtocolValueError) as refusal:
            reader(unsafe)
        assert refusal.value.reason_code == "payload_too_large"


def test_hook_stdin_cap_is_one_shared_definition() -> None:
    from yoetz.cli import hooks

    assert hooks.MAX_HOOK_STDIN_BYTES == MAX_HOOK_STDIN_BYTES
    # Raised from 256 KiB in tb4n1 (B5): Yoetz's own closure_prepare replies,
    # image views and large outputs outgrew it and lost their PostToolUse rows.
    assert MAX_HOOK_STDIN_BYTES == 1_048_576
    # A second private copy of this number is how the documented 1 MiB cap
    # could drift on one side only.
    assert not hasattr(hooks, "_MAX_STDIN_BYTES")
    assert not hasattr(hook_io_module, "_MAX_STDIN_BYTES")
    assert hook_io_module.MAX_HOOK_SKIM_BYTES == MAX_HOOK_SKIM_BYTES
    assert MAX_HOOK_SKIM_BYTES == 8_388_608


def test_cursor_ingress_skims_a_complete_oversize_body_and_drops_content() -> None:
    admitted = _at_cap_payload()
    parsed, omitted = read_cursor_hook_ingress(admitted)
    assert omitted is False
    assert parsed["hook_event_name"] == "PostToolUse"
    assert "x" in str(parsed["pad"])

    identity, omitted = read_cursor_hook_ingress(
        b'{"hook_event_name":"preToolUse","tool_name":"Write","tool_use_id":"toolu_1",'
        b'"tool_input":{"path":"docs/INTERFACES.md","contents":"'
        + b"Y" * MAX_HOOK_STDIN_BYTES
        + b'"},"user_email":"secret@example.com"}'
    )
    assert omitted is True
    assert identity["hook_event_name"] == "preToolUse"
    assert identity["tool_name"] == "Write"
    assert identity["tool_use_id"] == "toolu_1"
    assert identity["tool_input"] == {"path": "docs/INTERFACES.md"}
    assert "user_email" not in identity
    assert "YYYYY" not in str(identity)

    with pytest.raises(ProtocolValueError) as over_skim:
        read_cursor_hook_ingress(b"\x00" + b"x" * MAX_HOOK_SKIM_BYTES)
    assert over_skim.value.reason_code == "payload_too_large"

    with pytest.raises(CursorOversizedPayloadError) as malformed:
        read_cursor_hook_ingress(
            b'{"hook_event_name":"afterFileEdit","hook_event_name":"afterFileEdit","pad":"'
            + b"x" * MAX_HOOK_STDIN_BYTES
            + b'"}'
        )
    assert malformed.value.reason_code == "duplicate_object_key"

    prefix = b'{"hook_event_name":"preToolUse","tool_name":"Write","pad":"'
    suffix = b'"}'
    exact = prefix + b"z" * (MAX_HOOK_SKIM_BYTES - len(prefix) - len(suffix)) + suffix
    assert len(exact) == MAX_HOOK_SKIM_BYTES
    at_skim, at_skim_omitted = read_cursor_hook_ingress(exact)
    assert at_skim_omitted is True
    assert at_skim["tool_name"] == "Write"
    assert "pad" not in at_skim
    with pytest.raises(ProtocolValueError) as one_past_skim:
        read_cursor_hook_ingress(exact + b"z")
    assert one_past_skim.value.reason_code == "payload_too_large"


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b'{"hook_event_name":"afterFileEdit","pad":"\x00', "nul_byte_forbidden"),
        (b'{"hook_event_name":"afterFileEdit","pad":"\xff', "invalid_utf8"),
        (b'{"hook_event_name":"afterFileEdit","pad":"', "malformed_json"),
    ],
)
def test_cursor_ingress_never_trusts_an_unsafe_oversize_body(body: bytes, reason: str) -> None:
    # Each body is past the trusted cap and inside the skim cap. The last one
    # is a truncated prefix: it must not become an identity view.
    oversized = body + b"x" * MAX_HOOK_STDIN_BYTES + (b'"}' if reason != "malformed_json" else b"")
    assert MAX_HOOK_STDIN_BYTES < len(oversized) <= MAX_HOOK_SKIM_BYTES

    with pytest.raises(CursorOversizedPayloadError) as refused:
        read_cursor_hook_ingress(oversized)

    assert refused.value.reason_code == reason
