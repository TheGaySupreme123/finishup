"""The hook replay harness rebuilds host payloads faithfully and compares runs honestly (#1083).

``scripts/hook_replay.py`` feeds recorded hook payloads through two provisioned builds. These cases
hold its pure parts: the Codex payloads it rebuilds from a rollout, the native sessions it takes
from the repository's recorded shapes, the environment every instance process gets, the budgets it
pins, and the comparison that may rename only values a single run generated.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import random
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from finishup.cli import observe_hooks
from finishup.protocol.canonical import canonical_encode, entry_digest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "hook_replay.py"
_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "observations"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("hook_replay", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["hook_replay"] = module
    spec.loader.exec_module(module)
    return module


_MODULE = _load()


def _line(kind: str, payload: dict[str, Any]) -> str:
    return json.dumps({"payload": payload, "timestamp": "2026-10-16T10:00:00.000Z", "type": kind})


def _rollout() -> list[str]:
    return [
        _line("session_meta", {"cwd": "/app", "id": "sess-1", "runtime_workspace_roots": ["/app"]}),
        _line(
            "turn_context",
            {
                "approval_policy": "never",
                "cwd": "/app",
                "model": "gpt-test",
                "sandbox_policy": {"type": "danger-full-access"},
                "turn_id": "turn-1",
                "workspace_roots": ["/app"],
            },
        ),
        _line(
            "response_item",
            {
                "content": [
                    {
                        "text": "<environment_context>/app</environment_context>",
                        "type": "input_text",
                    }
                ],
                "role": "user",
                "type": "message",
            },
        ),
        _line(
            "response_item",
            {
                "content": [{"text": "Fix the bug", "type": "input_text"}],
                "role": "user",
                "type": "message",
            },
        ),
        _line(
            "response_item",
            {
                "arguments": json.dumps({"cmd": "pytest -q"}),
                "call_id": "c1",
                "name": "exec_command",
                "type": "function_call",
            },
        ),
        _line(
            "response_item",
            {
                "arguments": json.dumps({"view": "compact"}),
                "call_id": "c2",
                "name": "status",
                "namespace": "mcp__finishup",
                "type": "function_call",
            },
        ),
        _line(
            "response_item",
            {
                "arguments": json.dumps({"chars": ""}),
                "call_id": "c3",
                "name": "write_stdin",
                "type": "function_call",
            },
        ),
        _line(
            "response_item",
            {
                "call_id": "c1",
                "output": "Process exited with code 1\nOutput:\nFAILED\n",
                "type": "function_call_output",
            },
        ),
        _line(
            "response_item",
            {
                "call_id": "c2",
                "output": 'Wall time: 0.1 seconds\nOutput:\n{"ok":false}',
                "type": "function_call_output",
            },
        ),
        _line("response_item", {"call_id": "c3", "output": "", "type": "function_call_output"}),
        _line(
            "response_item",
            {
                "content": [{"text": "Done.", "type": "output_text"}],
                "role": "assistant",
                "type": "message",
            },
        ),
    ]


def test_codex_callbacks_follow_the_rollout_and_its_recorded_shapes() -> None:
    items, transcript = _MODULE.codex_corpus(
        _rollout(), name="codex1", workspace="codex1", max_calls=10
    )
    labels = [item["label"].split("/", 3)[3] for item in items]
    # Parallel calls: both Pre callbacks fire before either output lands; write_stdin has no
    # recorded hook shape in this repository and is not invented.
    assert labels == [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse/Bash",
        "PreToolUse/mcp__finishup__status",
        "PostToolUse/Bash",
        "PostToolUse/mcp__finishup__status",
        "Stop",
        "SessionEnd",
    ]
    payloads = [json.loads(item["stdin"]) for item in items]
    assert payloads[1]["prompt"] == "Fix the bug"
    assert payloads[2]["tool_input"] == {"command": "pytest -q"}
    assert payloads[2]["permission_mode"] == "bypassPermissions"
    assert payloads[2]["cwd"] == _MODULE.WORKSPACE
    assert payloads[2]["transcript_path"] == _MODULE.TRANSCRIPT
    assert payloads[4]["tool_response"] == "Process exited with code 1\nOutput:\nFAILED\n"
    assert payloads[5]["tool_response"] == {
        "content": [{"text": '{"ok":false}', "type": "text"}],
        "isError": True,
        "structuredContent": {"ok": False},
    }
    assert payloads[6]["last_assistant_message"] == ""
    assert payloads[6]["stop_hook_active"] is False
    uptos = [item["transcript"]["upto"] for item in items]
    assert uptos == sorted(uptos)
    assert len(transcript) == uptos[-1]
    assert json.loads(transcript[0])["payload"]["cwd"] == _MODULE.WORKSPACE
    assert json.loads(transcript[1])["payload"]["workspace_roots"] == [_MODULE.WORKSPACE]


def test_codex_start_calls_also_reach_the_start_correlation_hook() -> None:
    rollout = _rollout()
    rollout[5] = rollout[5].replace('"name": "status"', '"name": "start"')
    items, _ = _MODULE.codex_corpus(rollout, name="codex1", workspace="codex1", max_calls=10)
    argvs = [item["argv"] for item in items if "PostToolUse" in item["label"]]
    assert ["hooks", "post-tool-use"] in argvs


def test_native_sessions_replay_the_recorded_fixture_payloads() -> None:
    claude = _MODULE.claude_corpus()
    recorded = json.loads((_FIXTURES / "claude-code-bash-outcomes.case.json").read_text())
    expected = _MODULE._rehome(
        recorded["input"]["hook"]["post_tool_use_bash"]["payload"], "/workspace/project"
    )
    assert json.loads(claude[4]["stdin"]) == expected
    assert claude[4]["argv"][-1] == recorded["input"]["observation_profile"]
    cursor = _MODULE.cursor_corpus()
    recorded = json.loads((_FIXTURES / "cursor-shell-outcomes.case.json").read_text())
    expected = _MODULE._rehome(
        recorded["input"]["hook"]["post_tool_use_shell_with_exit_code"]["payload"],
        "/workspace/project",
    )
    assert json.loads(cursor[3]["stdin"]) == expected
    assert cursor[0]["argv"] == ["hooks", "startup-context", "--host", "cursor"]


def test_every_instance_process_gets_a_private_home_and_no_keychain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for name in (
        "FINISHUP_ISOLATED_ROOT",
        "YOETZ_ISOLATED_ROOT",
        "PYTHONPATH",
        "CODEX_HOME",
        "CLAUDE_CONFIG_DIR",
    ):
        monkeypatch.setenv(name, "/ambient")
    env = _MODULE.instance_env(tmp_path, {"CURSOR_PROJECT_DIR": "/w"})
    assert env["HOME"] == str(tmp_path)
    assert env["CODEX_HOME"] == str(tmp_path / ".codex")
    assert env["PYTHON_KEYRING_BACKEND"] == "keyring.backends.fail.Keyring"
    assert env["CURSOR_PROJECT_DIR"] == "/w"
    assert not {
        "FINISHUP_ISOLATED_ROOT",
        "YOETZ_ISOLATED_ROOT",
        "PYTHONPATH",
        "CLAUDE_CONFIG_DIR",
    } & set(env)


def test_pinned_budgets_name_real_hook_budgets_and_only_widen_them() -> None:
    for name, value in _MODULE.PINNED_HOOK_BUDGETS.items():
        shipped = getattr(observe_hooks, name)
        assert type(shipped) is type(value), name
        assert value >= shipped, name


# ------------------------------------------------------------------------------ comparison
#
# A synthetic replay record shaped like the real one: one Codex workspace whose ledger export
# carries a hash chain computed with the product's own canonical encoder. ``seed`` changes every
# value a run generates (identifiers, keyed commitments, clock times); everything else is input.

_STARTED = datetime(2026, 10, 16, 20, 0, tzinfo=UTC)
_CONTENT_DIGEST = "sha256:" + "c" * 64
_HOOK_IDENTITY = "hook:" + "d" * 48
_HOST_SESSION = "codex-session:01a1442c-ec41-7453-87d0-56458e120e29"
_COVERAGE: dict[str, Any] = {
    "artifact_observation": "published_only",
    "authorship_assurance": "service_authenticated",
    "check_types": ["none"],
    "evidence_immutability": "metadata_only",
    "known_gaps": [],
    "ledger_freshness": "current",
    "publication_channels": ["hook_observed"],
}


class _Gen:
    def __init__(self, seed: int) -> None:
        self._random = random.Random(seed)

    def hex(self, length: int) -> str:
        return "".join(self._random.choice("0123456789abcdef") for _ in range(length))

    def id(self, prefix: str) -> str:
        h = self.hex(32)
        return f"{prefix}_{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"

    def keyed(self) -> str:
        return "hmac-sha256:" + self.hex(64)

    def clock(self, offset_seconds: float) -> str:
        jitter = self._random.random()
        moment = _STARTED + timedelta(seconds=offset_seconds + jitter)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def _event(
    gen: _Gen,
    task: str,
    session: str,
    writer: str,
    sequence: int,
    previous: str,
    writer_state: tuple[int, str],
    name: str,
    payload: dict[str, Any],
    *,
    author: str = "yoetz:observation-coordinator",
    causal_parents: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    occurred_at: str | None = None,
) -> tuple[dict[str, Any], str]:
    payload_bytes = canonical_encode(payload)
    clock = gen.clock(sequence)
    preimage: dict[str, Any] = {
        "artifact_refs": [],
        "author": {"actor_id": author, "actor_type": "harness", "assurance": "harness_observed"},
        "causal_parents": sorted(causal_parents or []),
        "coverage": _COVERAGE,
        "event_id": gen.id("evt"),
        "evidence_refs": sorted(evidence_refs or []),
        "ledger": {
            "accepted_at": clock,
            "ingestion_sequence": str(sequence),
            "previous_entry_digest": previous,
        },
        "occurred_at": occurred_at or clock,
        "operation_id": gen.id("req"),
        "payload_ref": {
            "commitment": gen.keyed(),
            "encryption_format": "yoetz-object/1",
            "media_type": f"application/vnd.yoetz.{name}+json",
            "object_id": gen.id("obj"),
            "plaintext_size": len(payload_bytes),
        },
        "protocol": "yoetz.event",
        "protocol_version": "0.1",
        "publication_channel": "hook_observed",
        "redaction": "present",
        "schema": {"name": name, "version": "1.0.0"},
        "session_id": session,
        "task_id": task,
        "writer": {
            "previous_entry_digest": writer_state[1],
            "sequence": str(writer_state[0] + 1),
            "writer_id": writer,
        },
    }
    entry = {**preimage, "entry_digest": entry_digest(preimage)}
    exported = {
        "canonical_entry": canonical_encode(entry).decode(),
        "payload": payload_bytes.decode(),
        "payload_sha256": "sha256:" + hashlib.sha256(payload_bytes).hexdigest(),
    }
    return exported, cast(str, entry["entry_digest"])


def _make_run(
    seed: int,
    *,
    outcome: str = "failure",
    consent: str = "active",
    description: str = "Observed pending command via Codex hook (tool Bash)",
) -> dict[str, Any]:
    gen = _Gen(seed)
    task, session, writer = gen.id("tsk"), gen.id("ses"), gen.id("wri")
    action, evidence, result, finding = gen.id("act"), gen.id("evd"), gen.id("res"), gen.id("fnd")
    segments = sorted(gen.keyed() for _ in range(3))
    events: list[dict[str, Any]] = []
    digests: list[str] = []
    event_ids: list[str] = []

    def add(name: str, payload: dict[str, Any], **kwargs: Any) -> None:
        previous = digests[-1] if digests else "genesis"
        state = (len(digests), previous)
        exported, digest = _event(
            gen, task, session, writer, len(digests) + 1, previous, state, name, payload, **kwargs
        )
        events.append(exported)
        digests.append(digest)
        event_ids.append(json.loads(exported["canonical_entry"])["event_id"])

    add(
        "session_opened",
        {"external_ref": _HOST_SESSION, "workspace_ref": "/replay/w"},
        author="yoetz.engine",
    )
    add(
        "action_recorded",
        {
            "action_id": action,
            "action_kind": "command",
            "command": f"omitted:{gen.keyed()} and_chain {' '.join(segments)}",
            "description": description,
        },
    )
    add(
        "evidence_recorded",
        {
            "content_digest": _CONTENT_DIGEST,
            "evidence_id": evidence,
            "evidence_kind": "other",
            "observed_at": gen.clock(3),
            "strength": "content_digest",
        },
        causal_parents=[event_ids[1]],
    )
    add(
        "result_recorded",
        {
            "action_id": action,
            "evidence_refs": [evidence],
            "outcome": outcome,
            "result_id": result,
        },
        causal_parents=[event_ids[1], event_ids[2]],
        evidence_refs=[evidence],
    )
    add(
        "finding_recorded",
        {
            "finding_id": finding,
            "subject_frontier": {"head_digest": digests[3], "sequence": "4"},
            "subject_refs": sorted([event_ids[1], event_ids[3]]),
        },
    )
    head = {"head_digest": digests[-1], "sequence": str(len(digests))}
    history: list[dict[str, Any]] = []
    for exported in events:
        entry = json.loads(exported["canonical_entry"])
        history.append(
            {
                "accepted_at": entry["ledger"]["accepted_at"],
                "actor_id": entry["author"]["actor_id"],
                "event_id": entry["event_id"],
                "ingestion_sequence": entry["ledger"]["ingestion_sequence"],
                "occurred_at": entry["occurred_at"],
                "publication_channel": entry["publication_channel"],
                "schema_name": entry["schema"]["name"],
                "schema_version": entry["schema"]["version"],
            }
        )
    status = {
        "advice": {"finding_ids": [finding], "top_evidence": _HOOK_IDENTITY},
        "consent": consent,
        "delivery_lag": {"count": 3, "mean_ms": 900 + seed, "since": gen.clock(1)},
        "hook_diagnostics": {
            "count": 1,
            "drain_failures": [{"source_commitment": gen.keyed(), "ts": gen.clock(2)}],
        },
        "last_successful_drain": f"{seed % 7 + 1}.5s ago",
        "selection": {"capture_backlog": {"routes": {task: {"count": 0}}}},
    }
    mapped = (
        f"FinishUP task {task} is mapped to this session at frontier 1:{digests[0]} as "
        f"session_id {session} and writer_id {writer}."
    )
    items = [
        ("codex/w/000/SessionStart", json.dumps({"additional_context": mapped})),
        (
            "codex/w/001/PostToolUse/Bash",
            f"Next: resolve_failed_command. Evidence: {_HOOK_IDENTITY}.",
        ),
        ("codex/w/002/PostToolUse/Bash", f"Evidence: stream:{gen.hex(48)}. Result {result}."),
    ]
    return {
        "started_at": _STARTED.isoformat(),
        "finished_at": (_STARTED + timedelta(minutes=10)).isoformat(),
        "setup": {"w": {"grant_returncode": 0}},
        "service_stop": {"stop_returncode": 0, "exit_code": 0},
        "items": [
            {
                "label": label,
                "host": "codex",
                "workspace": "w",
                "event": "PostToolUse",
                "returncode": 0,
                "stdout": stdout,
                "stderr": "",
                "elapsed_ms": float(index + 1),
                "drain": {"returncode": 0, "stdout": '{"terminal":"drained"}\n'},
            }
            for index, (label, stdout) in enumerate(items)
        ],
        "ledgers": {
            "w": {
                "mapped": True,
                "mapping": {"session_id": session, "writer_id": writer},
                "observe_status_returncode": 0,
                "observe_status": json.dumps(status),
                "history": history,
                "history_complete": True,
                "head_frontier": head,
            }
        },
        "export": {
            "ok": True,
            "returncode": 0,
            "tasks": [{"task_id": task, "events": events, "head": head}],
        },
    }


def _rewrite_payload(run: dict[str, Any], index: int, change: dict[str, Any]) -> None:
    """Edit one exported payload, keeping its digest and size consistent (a careful forgery)."""

    event = run["export"]["tasks"][0]["events"][index]
    payload = {**json.loads(event["payload"]), **change}
    encoded = canonical_encode(payload)
    event["payload"] = encoded.decode()
    event["payload_sha256"] = "sha256:" + hashlib.sha256(encoded).hexdigest()


def _compare(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    return _MODULE.compare_runs(old, new)


def test_two_runs_that_differ_only_in_generated_values_are_identical() -> None:
    old, new = _make_run(1), _make_run(2)
    assert _MODULE.run_failures(old) == [] and _MODULE.run_failures(new) == []
    result = _compare(old, new)
    assert result["identical"], result
    assert result["bijection"]["consistent"]
    assert result["workspaces"]["w"]["events"] == 5


def test_sets_ordered_by_generated_value_are_compared_as_sets() -> None:
    # Find two seeds whose sorted identifier and keyed-segment lists come out in different orders.
    def orders(seed: int) -> tuple[list[str], str]:
        run = _make_run(seed)
        events = run["export"]["tasks"][0]["events"]
        parents = json.loads(events[3]["canonical_entry"])["causal_parents"]
        ids = [json.loads(e["canonical_entry"])["event_id"] for e in events]
        command = json.loads(events[1]["payload"])["command"]
        return [str(ids.index(p)) for p in parents], command

    first = orders(1)
    other = next(seed for seed in range(2, 200) if orders(seed)[0] != first[0])
    assert _compare(_make_run(1), _make_run(other))["identical"]


def test_a_replaced_chain_head_now_fails() -> None:
    # The review probe: replacing only the final chain head must fail, not compare equal.
    old, new = _make_run(1), _make_run(2)
    new["export"]["tasks"][0]["head"]["head_digest"] = "sha256:" + "a" * 64
    result = _compare(old, new)
    assert not result["identical"]
    assert any(r.startswith("export_head_mismatch") for r in result["refused"]["new"])
    forged = _make_run(2)
    forged["ledgers"]["w"]["head_frontier"] = {"head_digest": "sha256:" + "a" * 64, "sequence": "5"}
    assert not _compare(old, forged)["identical"]


def test_a_replaced_entry_or_payload_now_fails() -> None:
    old = _make_run(1)
    tampered = _make_run(2)
    event = tampered["export"]["tasks"][0]["events"][3]
    event["payload"] = event["payload"].replace('"failure"', '"success"')
    result = _compare(old, tampered)
    assert not result["identical"]
    assert any(r.startswith("payload_digest_mismatch") for r in result["refused"]["new"])
    # A forged payload with a matching digest still differs in content.
    forged = _make_run(2)
    _rewrite_payload(forged, 3, {"outcome": "success"})
    result = _compare(old, forged)
    assert not result["identical"]
    assert "w event[4] payload" in [m["part"] for m in result["workspaces"]["w"]["mismatches"]]
    # And an edited canonical entry breaks the chain it belongs to.
    edited = _make_run(2)
    entry = edited["export"]["tasks"][0]["events"][2]
    entry["canonical_entry"] = entry["canonical_entry"].replace("hook_observed", "local_cli", 1)
    assert not _compare(old, edited)["identical"]


def test_payload_contents_differing_from_a_real_outcome_are_not_hidden() -> None:
    old, new = _make_run(1), _make_run(2, outcome="success")
    result = _compare(old, new)
    assert not result["identical"]


def test_a_changed_content_digest_is_compared_exactly() -> None:
    # The review probe: one ``sha256:aaaa`` to ``sha256:bbbb`` payload change must fail.
    old, new = _make_run(1), _make_run(2)
    _rewrite_payload(old, 2, {"content_digest": "sha256:" + "a" * 64})
    _rewrite_payload(new, 2, {"content_digest": "sha256:" + "b" * 64})
    result = _compare(old, new)
    assert not result["identical"]
    assert [m["part"] for m in result["workspaces"]["w"]["mismatches"]] == ["w event[3] payload"]


def test_clock_values_are_normalized_only_in_named_service_fields() -> None:
    old, new = _make_run(1), _make_run(2)
    # A service clock field outside the run's wall-clock window is refused, not renamed.
    _rewrite_payload(new, 2, {"observed_at": "2026-10-17T20:00:00.000Z"})
    result = _compare(old, new)
    assert not result["identical"]
    assert result["refused"]["new"] == ["clock_outside_run:observed_at"]
    # A time inside a caller-written field is data: a one-second change fails.
    old = _make_run(1, description="observed at 2026-10-16T20:00:01.000Z")
    new = _make_run(2, description="observed at 2026-10-16T20:00:02.000Z")
    result = _compare(old, new)
    assert not result["identical"]
    assert [m["part"] for m in result["workspaces"]["w"]["mismatches"]] == ["w event[2] payload"]


def test_relinking_a_generated_identifier_fails() -> None:
    old, new = _make_run(1), _make_run(2)
    # The result now names an action no other record names: same shape, different linkage.
    _rewrite_payload(new, 3, {"action_id": _Gen(99).id("act")})
    result = _compare(old, new)
    assert not result["identical"]
    assert not result["bijection"]["consistent"] or any(
        not entry["identical"] for entry in result["workspaces"].values()
    )


def test_a_corpus_value_is_never_renamed() -> None:
    old, new = _make_run(1), _make_run(2)
    shared = _Gen(7).id("ses")
    other = _Gen(8).id("ses")
    old["items"][1]["stdout"] += f" input {shared}"
    new["items"][1]["stdout"] += f" input {other}"
    assert _compare(old, new)["identical"]  # Not in the corpus: generated, renamed.
    assert not _MODULE.compare_runs(old, new, frozenset({shared, other}))["identical"]


def test_a_failed_history_read_never_compares_equal() -> None:
    # The review probe: exit 1 and an error result for both reads used to pass as identical.
    old, new = _make_run(1), _make_run(2)
    for run in (old, new):
        ledger = run["ledgers"]["w"]
        ledger["history"] = []
        ledger["history_complete"] = False
        ledger["history_error"] = {"reason": "status_exit_nonzero"}
        del ledger["head_frontier"]
    result = _compare(old, new)
    assert not result["identical"]
    assert "history_incomplete:w" in result["refused"]["old"]
    assert "history_empty:w" in result["refused"]["new"]


def test_the_collector_records_a_failed_history_read(tmp_path: Path) -> None:
    # The review probe, against the collector itself: every read exits 1 with an error result.
    replayer = object.__new__(_MODULE.Replayer)

    def failing(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        body = b'{"ok":false,"error":{"code":"INTERNAL_ERROR"}}'
        return subprocess.CompletedProcess(argv, 1, body, b"failed read")

    replayer.finishup = failing
    mapped = (
        "task tsk_00000000-0000-4000-8000-000000000001 is mapped now as session_id "
        "ses_00000000-0000-4000-8000-000000000002 and writer_id "
        "wri_00000000-0000-4000-8000-000000000003"
    )
    ledger = replayer._ledger(tmp_path, [{"workspace": "w", "stdout": mapped, "stderr": ""}], "w")
    assert ledger["mapped"] is True
    assert ledger["history_error"]["reason"] == "status_exit_nonzero"
    assert ledger["history_complete"] is False and ledger["history"] == []
    assert ledger["observe_status_returncode"] == 1
    old, new = _make_run(1), _make_run(2)
    old["ledgers"]["w"] = ledger
    new["ledgers"]["w"] = ledger
    result = _compare(old, new)
    assert not result["identical"] and result["refused"]["old"]


@pytest.mark.parametrize(
    ("returncode", "stdout", "reason"),
    [
        (1, '{"ok":false,"error":{"code":"INTERNAL_ERROR"}}', "status_exit_nonzero"),
        (0, '{"ok":false,"error":{"code":"INTERNAL_ERROR"}}', "status_error_result"),
        (0, "not json", "status_output_unparsable"),
        (0, "[]", "status_output_not_object"),
        (0, '{"head_frontier":{"sequence":"1","head_digest":"genesis"}}', "status_page_missing"),
        (0, '{"page":{"items":[]}}', "status_head_frontier_missing"),
        (0, '{"page":{"items":[],"next_cursor":""}}', "status_page_cursor_invalid"),
        (0, '{"page":{"items":[],"view":"results","next_cursor":null}}', "status_page_wrong_view"),
    ],
)
def test_every_failed_history_page_is_named(returncode: int, stdout: str, reason: str) -> None:
    assert _MODULE.history_page_failure(returncode, stdout) == reason


def test_a_complete_history_page_is_accepted() -> None:
    page: dict[str, Any] = {
        "page": {"items": [], "next_cursor": None},
        "head_frontier": {"sequence": "1", "head_digest": "x"},
    }
    assert _MODULE.history_page_failure(0, json.dumps(page)) is None
    assert (
        _MODULE.history_page_failure(0, json.dumps({"page": {"items": [], "next_cursor": "c"}}))
        is None
    )


@pytest.mark.parametrize(
    "breakage",
    [
        "export_failed",
        "export_missing",
        "export_empty",
        "stop_unclean",
        "setup_failed",
        "unmapped",
        "observe_status_failed",
        "history_row_forged",
        "window_missing",
    ],
)
def test_any_failed_or_inconsistent_read_refuses_the_comparison(breakage: str) -> None:
    old, new = _make_run(1), _make_run(2)
    ledger = new["ledgers"]["w"]
    if breakage == "export_failed":
        new["export"] = {"ok": False, "error": "export_vault_not_passphrase", "returncode": 3}
    elif breakage == "export_missing":
        del new["export"]
    elif breakage == "export_empty":
        new["export"]["tasks"] = []
    elif breakage == "stop_unclean":
        new["service_stop"] = {"stop_returncode": 0, "exit_code": -15, "terminated": True}
    elif breakage == "setup_failed":
        new["setup"]["w"]["grant_returncode"] = 1
    elif breakage == "unmapped":
        ledger["mapped"] = False
        del ledger["mapping"]
    elif breakage == "observe_status_failed":
        ledger["observe_status_returncode"] = 1
        ledger["observe_status"] = ""
    elif breakage == "history_row_forged":
        ledger["history"][2]["schema_name"] = "claim_recorded"
    else:
        del new["started_at"]
    result = _compare(old, new)
    assert not result["identical"]
    assert result["refused"]["new"], result


def test_observe_status_is_compared_except_named_clock_and_latency_fields() -> None:
    assert _compare(_make_run(1), _make_run(2))["identical"]  # latency and clocks differ
    # The review probe: a final consent that changed from active to revoked must fail.
    result = _compare(_make_run(1), _make_run(2, consent="revoked"))
    assert not result["identical"]
    assert [m["part"] for m in result["workspaces"]["w"]["mismatches"]] == ["w observe status"]


def test_records_with_another_corpus_or_missing_modes_fail() -> None:
    corpus: dict[str, Any] = {"sha256": "sha256:" + "1" * 64, "generated_tokens": []}
    old: dict[str, Any] = {
        "corpus": corpus,
        "runs": {"pinned": _make_run(1)},
        "build": {"source_ref": "a"},
    }
    new: dict[str, Any] = {
        "corpus": corpus,
        "runs": {"pinned": _make_run(2)},
        "build": {"source_ref": "b"},
    }
    assert _MODULE.compare_records(old, new)["identical"]
    other: dict[str, Any] = {
        **new,
        "corpus": {"sha256": "sha256:" + "2" * 64, "generated_tokens": []},
    }
    assert not _MODULE.compare_records(old, other)["identical"]
    assert not _MODULE.compare_records(old, {**new, "runs": {}})["identical"]


def test_text_outside_generated_values_must_match_exactly() -> None:
    old, new = _make_run(1), _make_run(2)
    new["items"][1]["stdout"] = "{}"
    assert not _compare(old, new)["identical"]


def test_latency_reports_nearest_rank_percentiles() -> None:
    def run(offset: float) -> dict[str, Any]:
        return {
            "items": [
                {
                    "label": f"codex/x/{i}",
                    "host": "codex",
                    "event": "PreToolUse",
                    "elapsed_ms": float(i + 1) - offset,
                }
                for i in range(10)
            ]
        }

    rows = {(row["host"], row["event"]): row for row in _MODULE.latency_table(run(0), run(1))}
    row = rows[("codex", "PreToolUse")]
    assert row["n"] == 10
    assert row["old_median_ms"] == 5.5 and row["new_median_ms"] == 4.5
    assert row["old_p90_ms"] == 9.0 and row["new_p90_ms"] == 8.0
    assert row["median_saved_ms"] == 1.0


def test_the_ledger_export_names_real_product_seams() -> None:
    from finishup.adapters.objects.encrypted_files import EncryptedFilesObjectStore
    from finishup.adapters.sqlite import connection
    from finishup.config import installation
    from finishup.service import daemon, installation_recovery, vault

    compile(_MODULE._LEDGER_EXPORT, "ledger-export", "exec")
    assert callable(getattr(daemon, "_InstallationStateStore"))
    assert isinstance(getattr(daemon, "_INSTALLATION_MARKER_NAME"), str)
    assert callable(getattr(daemon, "_SystemClock"))
    assert callable(installation.read_instance_identity)
    assert callable(installation_recovery.InstallationRecoverySetStore)
    assert callable(connection.open_read_only)
    for name in ("unlock", "load_bundle_keys", "close"):
        assert callable(getattr(vault.VaultService, name))
    for name in ("resolve_verified", "open_verified"):
        assert callable(getattr(EncryptedFilesObjectStore, name))


def test_probe_versions_are_the_current_request_schemas() -> None:
    from finishup.protocol import schemas

    current = schemas.request_result_schema_versions(schemas.load_schema_catalog())
    for name, version in _MODULE._PROBE_VERSIONS.items():
        assert current[name] == version, name


def test_a_probe_prints_every_error_field_from_a_fresh_process() -> None:
    import subprocess

    items = {item["label"]: item for item in _MODULE.probe_items()}
    assert all(item["runner"] == "python" for item in items.values())
    outcomes: dict[str, dict[str, Any]] = {}
    for label in (
        "probe/coverage-valid",
        "probe/start-unpaired-workspace-ref",
        "probe/float-value",
    ):
        done = subprocess.run(
            [sys.executable, "-I", "-c", _MODULE._PROBE],
            input=items[label]["stdin"].encode(),
            capture_output=True,
            check=True,
        )
        outcomes[label] = json.loads(done.stdout)
    assert outcomes["probe/coverage-valid"] == {"outcome": "accepted"}
    paired = outcomes["probe/start-unpaired-workspace-ref"]
    assert paired["outcome"] == "SchemaInstanceInvalid"
    assert ["external_ref"] in [path for path, _reason in paired["location_reasons"]]
    assert outcomes["probe/float-value"] == {
        "outcome": "ProtocolValueError",
        "reason_code": "float_forbidden",
    }


def test_the_admission_clock_control_sets_real_thresholds_in_a_fresh_process() -> None:
    from finishup.adapters.integrations import observation_admission

    for name in ("SUMMARY_FLUSH_MS", "PENDING_ATTEMPT_FLUSH_MS"):
        assert type(getattr(observation_admission, name)) is int
    probe = (
        "import os, json\n"
        + _MODULE._ADMISSION_CLOCK_CONTROL
        + "from finishup.adapters.integrations import observation_admission as a\n"
        + "print(json.dumps([a.SUMMARY_FLUSH_MS, a.PENDING_ATTEMPT_FLUSH_MS]))\n"
    )
    for clock, value in _MODULE.ADMISSION_CLOCKS.items():
        env = {**os.environ, "HOOK_REPLAY_ADMISSION_CLOCK": str(value)}
        done = subprocess.run(
            [sys.executable, "-c", probe], env=env, capture_output=True, check=True
        )
        assert json.loads(done.stdout) == [value, value], clock
    assert "_ADMISSION_CLOCK_CONTROL" not in _MODULE._PINNED_BOOTSTRAP
    assert _MODULE._ADMISSION_CLOCK_CONTROL in _MODULE._PINNED_BOOTSTRAP
    assert _MODULE._ADMISSION_CLOCK_CONTROL in _MODULE._SERVICE_BOOTSTRAP


def test_the_fixed_observation_key_control_names_the_real_key_file() -> None:
    from finishup.adapters.integrations import observation_local

    compile(_MODULE._SEED_OBSERVATION_KEY, "seed-observation-key", "exec")
    assert len(_MODULE.FIXED_OBSERVATION_KEY) == getattr(observation_local, "_KEY_BYTES")
    assert callable(observation_local.observation_dir)
    assert callable(getattr(observation_local, "_atomic_write"))
    source = Path(observation_local.__file__).read_text(encoding="utf-8")
    assert '"key-material.bin"' in source


def test_the_paused_background_passes_exist_on_the_service() -> None:
    from finishup.service.daemon import ServiceDaemon

    for name in (
        "_bounded_observation_sweep",
        "_bounded_lineage_recovery",
        "_bounded_coordination_sweep",
    ):
        assert name in _MODULE._SERVICE_BOOTSTRAP
        assert callable(getattr(ServiceDaemon, name))
    compile(_MODULE._SERVICE_BOOTSTRAP, "service-bootstrap", "exec")
    compile(_MODULE._PINNED_BOOTSTRAP, "pinned-bootstrap", "exec")
