"""Installation-keyed command identity computed inside the hook process (#909).

The identity lets a later passing run of the same command supersede an earlier failure without
Yoetz ever retaining the command: the hook normalizes the host's command argument, commits to it
with the installation key, and forwards only the ``hmac-sha256:`` value. These tests start at the
real host normalizers with host-shaped payloads and assert the command text never reaches local
state, the envelope, or the materialized ledger action.
"""

from __future__ import annotations

import io
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.application.observation_materialize import materialize_observation_envelope
from yoetz.cli import observe_hooks
from yoetz.domain.events import ActionRecordedPayload
from yoetz.domain.observation import (
    ObservationEnvelope,
    ObservationSource,
    normalize_observed_command,
    observed_command_commitment,
)
from yoetz.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from yoetz.domain.values import JsonValue
from yoetz.protocol.canonical import canonical_encode

# A distinctive token: if any byte of it survives anywhere, command text leaked.
_CANARY = "zq909canary"
_KEY = b"i" * 32
_OTHER_INSTALLATION_KEY = b"j" * 32


# --- normalization ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argument", "expected"),
    [
        ("pytest -q tests/x.py", "pytest -q tests/x.py"),
        ("  pytest   -q\ttests/x.py  ", "pytest -q tests/x.py"),
        ("/bin/bash -lc 'npm run test-type'", "npm run test-type"),
        ("bash -lc 'cargo test  -q'", "cargo test -q"),
        ("sh -c 'go test ./...'", "go test ./..."),
        ("/usr/bin/zsh -c ls", "ls"),
        (["/bin/bash", "-lc", "npm run test-type"], "npm run test-type"),
        (("bash", "-lc", "pytest -q tests/x.py"), "pytest -q tests/x.py"),
        (["pytest", "-q", "tests/x.py"], "pytest -q tests/x.py"),
        ('echo "a  b"   c', 'echo "a  b" c'),
        (["echo", "a  b"], "echo 'a  b'"),
        ("unterminated 'quote   here", "unterminated 'quote   here"),
    ],
)
def test_normalization_strips_host_shell_wrappers_and_collapses_whitespace(
    argument: object, expected: str
) -> None:
    assert normalize_observed_command(argument) == expected


@pytest.mark.parametrize("argument", ["", "   ", [], [1, 2], "a\x00b", None, 7, "x" * 16_385])
def test_normalization_refuses_arguments_it_cannot_commit_to(argument: object) -> None:
    assert normalize_observed_command(argument) is None


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ('echo "$HOME"', "echo '$HOME'"),
        ('grep "a b" f', "grep a b f"),
        ("printf 'x\\ty'", "printf x\\ty"),
        ('bash -lc "echo $HOME"', "echo $HOME"),
        ('bash -lc "echo $HOME"', "bash -lc 'echo $HOME'"),
        ("pytest -q a\npytest -q b", "pytest -q a pytest -q b"),
    ],
)
def test_normalization_never_merges_commands_with_different_shell_meaning(
    first: str, second: str
) -> None:
    """Quoting, expansion and separators change what a command does; they keep distinct identities.

    A missed equivalence only over-discloses a failure; a false one lets a different command's
    success retire it.
    """

    assert normalize_observed_command(first) != normalize_observed_command(second)


def test_the_linux_and_wsl2_wrapper_forms_commit_to_one_identity() -> None:
    wrapped = normalize_observed_command(["/bin/bash", "-lc", "pytest -q tests/x.py"])
    wsl = normalize_observed_command("bash -lc 'pytest -q tests/x.py'")
    direct = normalize_observed_command("pytest -q tests/x.py")
    assert wrapped == wsl == direct


def test_commitment_is_keyed_stable_within_and_distinct_across_installations() -> None:
    command = "pytest -q tests/x.py"
    first = observed_command_commitment(_KEY, command)
    assert first == observed_command_commitment(_KEY, command)
    assert first.startswith("hmac-sha256:") and len(first) == 76
    assert first != observed_command_commitment(_OTHER_INSTALLATION_KEY, command)
    assert first != observed_command_commitment(_KEY, "pytest -q tests/y.py")
    # Never the dictionary-guessable plain digest of the command.
    import hashlib

    assert hashlib.sha256(command.encode()).hexdigest() not in first


# --- Codex-shaped hook payloads -----------------------------------------------------------------


def _codex_envelope(payload: Mapping[str, object], key: bytes = _KEY) -> ObservationEnvelope:
    return observe_hooks.map_hook_payload_to_envelope(
        "PostToolUse",
        cast(Mapping[str, JsonValue], payload),
        session_commitment="hmac-sha256:" + "5" * 64,
        event_ordinal=1,
        key_material=key,
    )


def _exec_command(cmd: str, call: str) -> dict[str, object]:
    # Codex 0.157 code-mode nested exec_command: the result is a JSON object under tool_response.
    return {
        "hook_event_name": "PostToolUse",
        "session_id": "codex-909",
        "turn_id": "turn-1",
        "tool_name": "exec_command",
        "tool_use_id": call,
        "tool_input": {"cmd": cmd, "workdir": "/app", "yield_time_ms": 30000},
        "tool_response": (
            '{"chunk_id":"d74c6f","wall_time_seconds":23.2,"exit_code":2,'
            f'"output":"> tsc --noEmit {_CANARY} error TS2322"}}'
        ),
    }


def test_codex_exec_command_and_shell_argv_share_one_identity() -> None:
    exec_envelope = _codex_envelope(_exec_command(f"npm run test-type -- {_CANARY}", "call-1"))
    shell_envelope = _codex_envelope(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "codex-909",
            "tool_name": "shell",
            "tool_use_id": "call-2",
            "tool_input": {"command": ["/bin/bash", "-lc", f"npm run test-type -- {_CANARY}"]},
        }
    )
    commitment = exec_envelope.structural_payload["command_commitment"]
    assert commitment == shell_envelope.structural_payload["command_commitment"]
    assert commitment == observed_command_commitment(_KEY, f"npm run test-type -- {_CANARY}")
    for envelope in (exec_envelope, shell_envelope):
        encoded = canonical_encode(cast(JsonValue, envelope.structural_payload))
        assert _CANARY.encode() not in encoded
        assert b"npm" not in encoded


def test_codex_identity_differs_across_installations_and_commands() -> None:
    base = _codex_envelope(_exec_command("pytest -q tests/a.py", "call-1"))
    other = _codex_envelope(
        _exec_command("pytest -q tests/a.py", "call-1"), _OTHER_INSTALLATION_KEY
    )
    different = _codex_envelope(_exec_command("pytest -q tests/b.py", "call-1"))
    commitments = {
        envelope.structural_payload["command_commitment"] for envelope in (base, other, different)
    }
    assert len(commitments) == 3


def test_edit_and_non_shell_tools_never_carry_a_command_commitment() -> None:
    patch = _codex_envelope(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "codex-909",
            "tool_name": "apply_patch",
            "tool_use_id": "call-patch",
            "tool_input": {"command": f"*** Begin Patch\n+{_CANARY}\n*** End Patch"},
            "tool_response": "Exit code: 0\nOutput:\nSuccess.",
        }
    )
    assert "command_commitment" not in patch.structural_payload
    assert patch.structural_payload["exit_status"] == 0
    mcp = _codex_envelope(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "codex-909",
            "tool_name": "mcp__other__run",
            "tool_use_id": "call-mcp",
            "tool_input": {"command": _CANARY},
        }
    )
    assert "command_commitment" not in mcp.structural_payload


def test_a_forged_plain_digest_is_never_accepted_as_the_identity() -> None:
    envelope = _codex_envelope(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "codex-909",
            "tool_name": "exec_command",
            "tool_use_id": "call-forged",
            "command_commitment": "sha256:" + "0" * 64,
        }
    )
    assert "command_commitment" not in envelope.structural_payload


def test_materialized_command_action_carries_only_the_keyed_identity() -> None:
    envelope = _codex_envelope(_exec_command(f"pytest -q {_CANARY}", "call-1"))
    batch = materialize_observation_envelope(
        envelope, task_id="tsk_00000000-0000-4000-8000-000000000909"
    )
    actions = [
        cast(ActionRecordedPayload, item.draft.payload)
        for item in batch.drafts
        if item.draft.schema.name == "action_recorded"
    ]
    (command,) = [action.command or "" for action in actions]
    identity = "omitted:" + str(envelope.structural_payload["command_commitment"])
    # ADR-045: a command of three or more arguments also carries domain-separated canonical
    # commitments (a prefix and flags); every other word of the field is a keyed commitment.
    assert command.split(" ")[0] == identity
    assert all(
        word == "single" or word.startswith("hmac-sha256:") for word in command.split(" ")[1:]
    )
    assert _CANARY not in command
    legacy = observe_hooks.map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "codex-909",
            "tool_name": "exec_command",
            "tool_use_id": "call-legacy",
        },
        session_commitment="hmac-sha256:" + "5" * 64,
        event_ordinal=2,
        key_material=_KEY,
    )
    legacy_batch = materialize_observation_envelope(
        legacy, task_id="tsk_00000000-0000-4000-8000-000000000909"
    )
    assert [
        cast(ActionRecordedPayload, item.draft.payload).command
        for item in legacy_batch.drafts
        if item.draft.schema.name == "action_recorded"
    ] == ["omitted:structural"]


# --- Claude Code and Cursor ordinary profiles through the real handlers --------------------------


def _state_bytes(root: Path) -> bytes:
    return b"".join(
        path.read_bytes() for path in root.rglob("*") if path.is_file() and not path.is_symlink()
    )


def test_claude_ordinary_bash_failure_and_rerun_share_one_identity(tmp_path: Path) -> None:
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)

    def emit(event: str, payload: Mapping[str, object]) -> None:
        assert (
            observe_hooks.handle_claude_observe(
                event_name=event,
                stdin_bytes=canonical_encode(cast(JsonValue, payload)),
                stdout=io.BytesIO(),
                workspace=str(tmp_path),
                _state=state,
                skip_service=True,
                observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            )
            == 0
        )

    command = f"pytest -q tests/{_CANARY}.py"
    emit(
        "PostToolUseFailure",
        {
            "hook_event_name": "PostToolUseFailure",
            "session_id": "claude-909",
            "tool_name": "Bash",
            "tool_use_id": "toolu-red",
            "tool_input": {"command": command, "description": "Run the focused test"},
            "error": f"Exit code 1\nFAILED tests/{_CANARY}.py::test_x",
        },
    )
    emit(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "claude-909",
            "tool_name": "Bash",
            "tool_use_id": "toolu-green",
            "tool_input": {"command": f"pytest  -q  tests/{_CANARY}.py"},
            "tool_response": {"stdout": "1 passed", "stderr": "", "interrupted": False},
        },
    )
    emit(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": "claude-909",
            "tool_name": "Bash",
            "tool_use_id": "toolu-other",
            "tool_input": {"command": "pytest -q tests/other.py"},
            "tool_response": {"stdout": "1 passed", "stderr": "", "interrupted": False},
        },
    )
    envelopes = LocalObservationStore(_state=state).list_envelopes(workspace)
    red, green, other = (envelope.structural_payload for envelope in envelopes)
    assert red["success"] is False and green["success"] is True
    assert red["command_commitment"] == green["command_commitment"]
    assert red["command_commitment"] != other["command_commitment"]
    assert red["command_commitment"] == observed_command_commitment(
        LocalObservationStore(_state=state).key_material(), command
    )
    assert _CANARY.encode() not in _state_bytes(state)


def test_cursor_ordinary_shell_failure_carries_the_keyed_identity(tmp_path: Path) -> None:
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    payload: dict[str, JsonValue] = {
        "hook_event_name": "postToolUse",
        "session_id": "cursor-909",
        "conversation_id": "cursor-909-conversation",
        "tool_name": "Shell",
        "tool_use_id": "cursor-red",
        "tool_input": cast(JsonValue, {"command": f"npm test -- {_CANARY}"}),
        "tool_output": f'{{"exitCode":1,"stdout":"{_CANARY} failed"}}',
    }
    assert (
        observe_hooks.handle_cursor_observe(
            event_name="postToolUse",
            stdin_bytes=canonical_encode(payload),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=state,
            skip_service=True,
            observation_profile=CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        == 0
    )
    (envelope,) = LocalObservationStore(_state=state).list_envelopes(workspace)
    assert envelope.source is ObservationSource.CURSOR_HOOK
    assert envelope.structural_payload["exit_status"] == 1
    assert envelope.structural_payload["command_commitment"] == observed_command_commitment(
        LocalObservationStore(_state=state).key_material(), f"npm test -- {_CANARY}"
    )
    assert _CANARY.encode() not in _state_bytes(state)


def test_legacy_spool_keeps_only_the_keyed_identity_for_replay(tmp_path: Path) -> None:
    """The spool drops tool input, so the hook commits to the command before spooling."""

    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    assert (
        observe_hooks.handle_spool(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "session_id": "spool-909",
                    "tool_name": "shell",
                    "tool_use_id": "call-spool",
                    "exit_status": 1,
                    "tool_input": {"cmd": f"pytest -q {_CANARY}"},
                }
            ),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )
    (spooled,) = list((tmp_path / "hook-spool").glob("*.jsonl"))
    body = spooled.read_bytes()
    assert _CANARY.encode() not in body
    expected = observed_command_commitment(store.key_material(), f"pytest -q {_CANARY}")
    assert expected.encode() in body
    replayed = observe_hooks.map_hook_payload_to_envelope(
        "PostToolUse",
        {"session_id": "spool-909", "tool_name": "shell", "command_commitment": expected},
        session_commitment="hmac-sha256:" + "5" * 64,
        event_ordinal=1,
        key_material=store.key_material(),
    )
    assert replayed.structural_payload["command_commitment"] == expected


# --- Segment commitments for planned-verification matching (#977 E3) ---------------------------


def test_a_composed_command_carries_keyed_segment_commitments_never_text() -> None:
    command = f"cd /app && python evaluate.py {_CANARY} && git diff --check"
    envelope = _codex_envelope(_exec_command(command, "call-seg"))
    structural = envelope.structural_payload
    segments = cast(tuple[str, ...], structural["command_segment_commitments"])
    assert structural["command_composition"] == "and_chain"
    assert segments == tuple(sorted(segments))
    assert observed_command_commitment(_KEY, f"python evaluate.py {_CANARY}") in segments
    assert structural["command_commitment"] not in segments
    assert _CANARY.encode() not in canonical_encode(cast(JsonValue, dict(structural)))

    batch = materialize_observation_envelope(
        envelope, task_id="tsk_00000000-0000-4000-8000-000000000909"
    )
    (action,) = [
        cast(ActionRecordedPayload, item.draft.payload)
        for item in batch.drafts
        if item.draft.schema.name == "action_recorded"
    ]
    assert action.command == " ".join(
        ("omitted:" + str(structural["command_commitment"]), "and_chain", *segments)
    )
    assert _CANARY not in (action.command or "")
    # A one-word command, with no wrapper or alias to see through, keeps the historical
    # single-identity field byte for byte (ADR-045 adds canonical commitments only where a
    # canonical form differs or the command has arguments to commit).
    simple = _codex_envelope(_exec_command("pytest", "call-simple"))
    assert "command_segment_commitments" not in simple.structural_payload
    assert "command_composition" not in simple.structural_payload
    flagged = _codex_envelope(_exec_command("pytest -q", "call-flagged"))
    assert flagged.structural_payload["command_composition"] == "single"
    # A wrapped one carries the canonical full form, and never any text.
    wrapped = _codex_envelope(_exec_command(f"timeout 60 python3 {_CANARY}.py", "call-wrapped"))
    assert wrapped.structural_payload["command_composition"] == "single"
    assert (
        len(cast(tuple[str, ...], wrapped.structural_payload["command_segment_commitments"])) >= 1
    )
    assert _CANARY.encode() not in canonical_encode(
        cast(JsonValue, dict(wrapped.structural_payload))
    )


def test_claude_ordinary_redirected_run_commits_to_the_bare_command(tmp_path: Path) -> None:
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    command = f"bash /app/{_CANARY}.sh > /tmp/{_CANARY}.log 2>&1"
    assert (
        observe_hooks.handle_claude_observe(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "hook_event_name": "PostToolUse",
                    "session_id": "claude-977",
                    "tool_name": "Bash",
                    "tool_use_id": "toolu-seg",
                    "tool_input": {"command": command},
                    "tool_response": {"stdout": "", "stderr": "", "interrupted": False},
                }
            ),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=state,
            skip_service=True,
            observation_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        )
        == 0
    )
    (envelope,) = LocalObservationStore(_state=state).list_envelopes(workspace)
    key = LocalObservationStore(_state=state).key_material()
    assert envelope.structural_payload["command_composition"] == "single"
    segments = cast(tuple[str, ...], envelope.structural_payload["command_segment_commitments"])
    # The segment commitment of the bare command (ADR-045 adds a domain-separated canonical
    # commitment beside it for the flag-less program and script).
    assert observed_command_commitment(key, f"bash /app/{_CANARY}.sh") in segments
    assert all(item.startswith("hmac-sha256:") for item in segments)
    assert _CANARY.encode() not in _state_bytes(state)


def test_spool_replay_forwards_only_valid_segment_commitments(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    assert (
        observe_hooks.handle_spool(
            event_name="PostToolUse",
            stdin_bytes=canonical_encode(
                {
                    "session_id": "spool-977",
                    "tool_name": "shell",
                    "tool_use_id": "call-spool-seg",
                    "exit_status": 0,
                    "tool_input": {"cmd": f"npm test {_CANARY} && npm run build"},
                }
            ),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=tmp_path,
        )
        == 0
    )
    (spooled,) = list((tmp_path / "hook-spool").glob("*.jsonl"))
    assert _CANARY.encode() not in spooled.read_bytes()
    key = store.key_material()
    whole = observed_command_commitment(key, f"npm test {_CANARY} && npm run build")
    segments = sorted(
        observed_command_commitment(key, part) for part in (f"npm test {_CANARY}", "npm run build")
    )
    for value in segments:
        assert value.encode() in spooled.read_bytes()

    def replay(supplied: object) -> Mapping[str, object]:
        return observe_hooks.map_hook_payload_to_envelope(
            "PostToolUse",
            {
                "session_id": "spool-977",
                "tool_name": "shell",
                "command_commitment": whole,
                "command_segment_commitments": cast(JsonValue, supplied),
                "command_composition": "and_chain",
            },
            session_commitment="hmac-sha256:" + "5" * 64,
            event_ordinal=1,
            key_material=key,
        ).structural_payload

    assert replay(segments)["command_segment_commitments"] == tuple(segments)
    for invalid in (list(reversed(segments)), ["npm test"], [], "x"):
        assert "command_segment_commitments" not in replay(invalid)
