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
from collections.abc import Callable
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
    accepted_at: str | None = None,
) -> tuple[dict[str, Any], str]:
    payload_bytes = canonical_encode(payload)
    clock = accepted_at or gen.clock(sequence)
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
    payload_hook: Callable[[str, dict[str, Any], _Gen], None] | None = None,
    seeded: bool = True,
    captured: str | None = None,
    catalog: str = "lazy",
) -> dict[str, Any]:
    """A synthetic replay record; ``payload_hook`` may edit each payload before it is sealed.

    ``seeded`` runs share one observation key (``--fixed-observation-key``): their observation-keyed
    values (command commitments, source identities) and the advice finding id derived from them
    (``stable_advice_finding_id``) are the same in every seed, while the other identifiers and
    vault-keyed payload commitments still differ. ``captured`` (``"input-first"`` or
    ``"output-first"``) adds a call's captured tool input and output evidence before its result,
    in that order, as the materializer emits them in random object-id order (``"apart"``: input
    first, each accepted at its own time). ``catalog`` is how each callback loaded schemas: the
    pinned catalog trace of a ``"lazy"`` or an ``"eager"`` build.
    """

    gen = _Gen(seed)
    keyed = _Gen(10_000) if seeded else gen
    task, session, writer = gen.id("tsk"), gen.id("ses"), gen.id("wri")
    action, evidence, result, finding = gen.id("act"), gen.id("evd"), gen.id("res"), gen.id("fnd")
    segments = sorted(keyed.keyed() for _ in range(3))
    if seeded:
        # The coordinator's advice finding id digests a rule code and an observation-keyed detail
        # token (``observation_advice.stable_advice_finding_id``).
        finding = keyed.id("fnd")
    events: list[dict[str, Any]] = []
    digests: list[str] = []
    event_ids: list[str] = []

    def add(name: str, payload: dict[str, Any], **kwargs: Any) -> None:
        if payload_hook is not None:
            payload_hook(name, payload, gen)
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
            "command": f"omitted:{keyed.keyed()} and_chain {' '.join(segments)}",
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
    refs, parents = [evidence], [event_ids[1], event_ids[2]]
    if captured is not None:
        shared = gen.clock(4)
        kinds = [("tool_input", 33, "1"), ("tool_output", 144, "2")]
        for kind, size, digit in kinds[::-1] if captured == "output-first" else kinds:
            if captured == "apart":
                shared = gen.clock(4 + len(refs))
            refs.append(gen.id("evd"))
            add(
                "evidence_recorded",
                {
                    "captured_object_id": gen.id("obj"),
                    "content_digest": "sha256:" + digit * 64,
                    "description": f"Observation-captured {kind} bytes part=1/1",
                    "digest_binding": {
                        "byte_count": size,
                        "content_availability": "captured",
                        "provenance": "observation_captured",
                        "subject": "bounded_excerpt",
                    },
                    "evidence_id": refs[-1],
                    "evidence_kind": "other",
                    "observed_at": shared,
                    "strength": "immutable_snapshot",
                },
                causal_parents=[event_ids[1]],
                accepted_at=shared,
                occurred_at=shared,
            )
            parents.append(event_ids[-1])
    add(
        "result_recorded",
        {
            "action_id": action,
            "evidence_refs": sorted(refs),
            "outcome": outcome,
            "result_id": result,
        },
        causal_parents=parents,
        evidence_refs=refs,
    )
    position = len(event_ids)
    add(
        "finding_recorded",
        {
            "finding_id": finding,
            "subject_frontier": {"head_digest": digests[-1], "sequence": str(position)},
            "subject_refs": sorted([event_ids[1], event_ids[-1]]),
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
            "drain_failures": [{"source_commitment": keyed.keyed(), "ts": gen.clock(2)}],
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
        ("codex/w/002/PostToolUse/Bash", f"Evidence: stream:{keyed.hex(48)}. Result {result}."),
    ]
    return {
        "controls": {
            "fixed_observation_key": seeded,
            "admission_clock": "due",
            "observation_key_seeded": seeded,
        },
        "workspace_root": "/replay/work/pinned",
        "started_at": _STARTED.isoformat(),
        "finished_at": (_STARTED + timedelta(minutes=10)).isoformat(),
        "setup": {
            "w": {
                "grant": {"returncode": 0, "stdout": "Observation granted.\n", "stderr": ""},
            }
        },
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
                "catalog_trace": [
                    {"full_catalog_built": False, "lazy_documents": 92}
                    if catalog == "lazy"
                    else {"full_catalog_built": True, "lazy_documents": None}
                ],
                "drain": {"returncode": 0, "stdout": '{"terminal":"drained"}\n', "stderr": ""},
            }
            for index, (label, stdout) in enumerate(items)
        ],
        "ledgers": {
            "w": {
                "mapped": True,
                "mapping": {"session_id": session, "writer_id": writer},
                "observe_status_returncode": 0,
                "observe_status": json.dumps(status),
                "observe_status_stderr": "",
                "observe_status_read_after": items[-1][0],
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

    # Without a shared observation key the keyed command segments are per-instance values sorted
    # by value, so their order is compared as a set too.
    assert _compare(_make_run(1, seeded=False), _make_run(other, seeded=False))["identical"]


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
    snapshot = {**_MODULE._completed(failing([])), "read_after": "codex/w/002/PostToolUse/Bash"}
    records = [{"workspace": "w", "stdout": mapped, "stderr": ""}]
    ledger = replayer._ledger(tmp_path, records, "w", snapshot)
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
        "drain_failed",
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
        new["setup"]["w"]["grant"]["returncode"] = 1
    elif breakage == "drain_failed":
        # One failed drain is enough, even when the same drain also failed in the other run.
        for run in (old, new):
            run["items"][1]["drain"] = {"returncode": 2, "stdout": "", "stderr": "failed"}
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


@pytest.mark.parametrize(
    ("flags", "refusal"),
    [
        (["--admission-clock", "due"], "--admission-clock applies to --mode pinned only"),
        (["--fixed-observation-key"], "--fixed-observation-key applies to --mode pinned only"),
        (["--delay-ms", "50"], "--delay-ms applies to --mode pinned only"),
    ],
)
def test_pinned_only_flags_are_refused_before_any_instance_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, flags: list[str], refusal: str
) -> None:
    def provision(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("an instance was provisioned for a refused invocation")

    monkeypatch.setattr(_MODULE, "provision", provision)
    argv = ["replay", "--checkout", ".", "--revision", "HEAD", "--tag", "t"]
    argv += ["--corpus", str(tmp_path / "absent.json"), "--work-root", str(tmp_path / "w")]
    argv += ["--out", str(tmp_path / "out.json"), "--mode", "pinned", "--mode", "shipped"]
    with pytest.raises(SystemExit) as refused:
        _MODULE.main([*argv, *flags])
    assert str(refused.value) == refusal
    assert not (tmp_path / "w").exists()


@pytest.mark.parametrize(
    ("command", "revisions", "replayed_root"),
    [
        ("replay", ["--revision", "HEAD", "--mode", "pinned"], "scratch"),
        ("latency", ["--old-revision", "a", "--new-revision", "b"], "scratch/old"),
    ],
)
def test_a_relative_work_root_reaches_the_replayer_as_an_absolute_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
    revisions: list[str],
    replayed_root: str,
) -> None:
    # Instance commands run from ``<work root>/home`` and callbacks from their workspace, so a
    # relative root would send ``observe grant`` to ``scratch/home/scratch/pinned/<workspace>``.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "corpus.json").write_text(json.dumps({"items": [], "transcripts": {}}))
    roots: list[Path] = []

    class Built(Exception):
        pass

    def provision(checkout: Path, _revision: str, base: Path, tag: str, _python: str) -> Any:
        return _MODULE.Instance(tag, base, checkout, Path("/nonexistent/finishup"), {})

    class Replayer:
        def __init__(self, _instance: Any, work_root: Path, _log: Any) -> None:
            roots.append(work_root)
            raise Built

    monkeypatch.setattr(_MODULE, "provision", provision)
    monkeypatch.setattr(_MODULE, "Replayer", Replayer)
    argv = [command, "--checkout", ".", "--tag", "t", "--corpus", "corpus.json", *revisions]
    argv += ["--work-root", "scratch", "--out", "out.json"]
    with pytest.raises(Built):
        _MODULE.main(argv)
    assert roots == [tmp_path.resolve() / replayed_root]


def test_drain_and_setup_output_are_compared_parts() -> None:
    old, new = _make_run(1), _make_run(2)
    new["items"][0]["drain"]["stderr"] = "warning: drain retried\n"
    result = _compare(old, new)
    assert [m["part"] for m in result["workspaces"]["w"]["mismatches"]] == [
        "codex/w/000/SessionStart drain stderr"
    ]
    old, new = _make_run(1), _make_run(2)
    new["setup"]["w"]["grant"]["stdout"] = "Observation already granted.\n"
    result = _compare(old, new)
    assert [m["part"] for m in result["workspaces"]["w"]["mismatches"]] == ["w setup grant stdout"]


def test_an_unclean_pre_pause_stop_refuses_to_serve_a_second_service(tmp_path: Path) -> None:
    replayer = object.__new__(_MODULE.Replayer)
    replayer.home = tmp_path / "home"
    replayer.fixed_observation_key = False
    replayer.instance = cast(Any, type("I", (), {"launcher": tmp_path / "finishup", "tag": "t"}))
    spawned: list[list[str]] = []

    def spawn(command: list[str], _log: str) -> None:
        spawned.append(command)

    def wait(_accept: object) -> dict[str, Any]:
        return {"vault_mode": "uninitialized"}

    def stop() -> dict[str, Any]:
        return {"stop_returncode": 0, "exit_code": -15, "terminated": True}

    replayer._spawn_service = spawn
    replayer._wait_status = wait
    replayer.stop = stop
    with pytest.raises(SystemExit, match="pre-pause service stop unclean"):
        replayer.start(pause_background=True)
    assert len(spawned) == 1  # The paused service was never started beside the first one.
    assert _MODULE.stop_unclean({"stop_returncode": 0, "exit_code": 0}) is False
    assert _MODULE.stop_unclean({"stop_returncode": 1, "exit_code": 0}) is True


def test_each_workspace_status_is_read_right_after_its_own_last_item(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Lifecycle reads drain age against the wall clock, so the read must not wait for the
    # workspaces replayed after this one.
    calls: list[str] = []

    def run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        where = argv[argv.index("--workspace") + 1] if "--workspace" in argv else _kwargs["cwd"]
        calls.append(" ".join(argv[1:3]) + " " + Path(where).name)
        return subprocess.CompletedProcess(argv, 0, b"{}", b"")

    monkeypatch.setattr(_MODULE.subprocess, "run", run)
    replayer = object.__new__(_MODULE.Replayer)
    replayer.instance = cast(Any, type("I", (), {"launcher": tmp_path / "finishup"}))
    replayer.home = tmp_path
    replayer.admission_clock = None

    def log(_message: str) -> None:
        return None

    replayer.log = log
    items = [
        {"label": label, "host": "codex", "workspace": key, "argv": ["hooks", "observe", "-x"]}
        for label, key in (("a/1", "a"), ("a/2", "a"), ("b/1", "b"))
    ]
    state = _MODULE._ReplayState(
        mode="shipped",
        root=tmp_path,
        items=items,
        transcripts={},
        workspaces=["a", "b"],
        setup={},
        transcript_written={},
        transcript_paths={},
        claude_transcript=tmp_path / "t.jsonl",
        retained=tmp_path / "python",
        trace_path=tmp_path / "trace.jsonl",
        records=[],
        last_item={"a": 2, "b": 3},
        status_snapshots={},
    )
    for number, item in enumerate(items, start=1):
        replayer.step(state, number, item)
    assert calls == [
        "hooks observe a",
        "observe drain a",
        "hooks observe a",
        "observe drain a",
        "observe status a",
        "hooks observe b",
        "observe drain b",
        "observe status b",
    ]
    assert state.status_snapshots["a"]["read_after"] == "a/2"
    assert state.status_snapshots["b"]["read_after"] == "b/1"


def test_a_status_read_taken_after_another_item_is_refused() -> None:
    old, new = _make_run(1), _make_run(2)
    new["ledgers"]["w"]["observe_status_read_after"] = "codex/w/001/PostToolUse/Bash"
    result = _compare(old, new)
    assert result["refused"]["new"] == ["observe_status_not_after_last_item:w"]
    # Lifecycle is compared exactly, never normalized.
    old, new = _make_run(1), _make_run(2)
    status = json.loads(new["ledgers"]["w"]["observe_status"])
    status["status"] = {"lifecycle": "degraded"}
    new["ledgers"]["w"]["observe_status"] = json.dumps(status)
    status = json.loads(old["ledgers"]["w"]["observe_status"])
    status["status"] = {"lifecycle": "active"}
    old["ledgers"]["w"]["observe_status"] = json.dumps(status)
    assert not _compare(old, new)["identical"]


def _with_status(run: dict[str, Any], change: dict[str, Any]) -> dict[str, Any]:
    ledger = run["ledgers"]["w"]
    ledger["observe_status"] = json.dumps({**json.loads(ledger["observe_status"]), **change})
    return run


def _pass_timings(outcome: str, ms: int) -> dict[str, Any]:
    return {
        "bucket_upper_bounds_ms": [5, 10],
        "dropped_sample_count": ms % 2,
        "entries": [
            {
                "bucket_counts": [0, ms],
                "count": 1,
                "event": "PreToolUse",
                "first_seen": "2026-10-16T20:00:01.000000Z",
                "host": "claude",
                "last_seen": "2026-10-16T20:00:01.000000Z",
                "max_ms": ms,
                "max_ts": "2026-10-16T20:00:01.000000Z",
                "mean_ms": ms,
                "outcomes": {"failed": 0, outcome: 1},
                "p50_ms_at_most": ms,
                "p95_ms_at_most": ms,
                "path": "ordinary",
                "recent": {"count": 1, "max_ms": ms, "since": "2026-10-16T19:00:00Z"},
                "sum_ms": ms,
            }
        ],
        "evicted_entry_count": 0,
        "since": "2026-10-16T20:00:01.000000Z",
        "status": "retained",
    }


def test_latency_figures_are_dropped_only_at_their_own_paths() -> None:
    assert _MODULE.latency_path("/hook_diagnostics/pass_timings/entries[]/max_ms")
    assert _MODULE.latency_path("/hook_diagnostics/timings/paths/sync_fallback_spool/recent_p95_ms")
    assert _MODULE.latency_path("/selection/state_bytes")
    assert not _MODULE.latency_path("/selection/effective_budget/limits/state_bytes")
    assert not _MODULE.latency_path("/hook_diagnostics/pass_timings/entries[]/count")
    assert not _MODULE.latency_path("/hook_diagnostics/pass_timings/entries[]/outcomes")
    assert not _MODULE.latency_path("/hook_diagnostics/timings/count")
    assert not _MODULE.latency_path("/advice/max_ms")  # A key name alone never drops a field.
    # Every pass's wall time differs between the runs; nothing else does.
    old = _with_status(_make_run(1), {"hook_diagnostics": {"pass_timings": _pass_timings("a", 7)}})
    new = _with_status(_make_run(2), {"hook_diagnostics": {"pass_timings": _pass_timings("a", 8)}})
    assert _compare(old, new)["identical"]


def test_a_pass_outcome_that_differs_is_not_hidden_as_latency() -> None:
    # Probe P2: one pass ingested in one run and was not ingested in the other.
    timings = {"hook_diagnostics": {"pass_timings": _pass_timings("ingested", 7)}}
    old = _with_status(_make_run(1), timings)
    timings = {"hook_diagnostics": {"pass_timings": _pass_timings("not_ingested", 7)}}
    new = _with_status(_make_run(2), timings)
    result = _compare(old, new)
    assert not result["identical"]
    assert result["workspaces"]["w"]["mismatches"][0]["path"].startswith(
        "/hook_diagnostics/pass_timings/entries[0]/outcomes"
    )


def test_a_configured_limit_is_compared_while_the_usage_size_is_not() -> None:
    def budget(limit: int, used: int) -> dict[str, Any]:
        effective = {"limits": {"state_bytes": limit}, "utilization_bps": used // 100}
        return {"selection": {"state_bytes": used, "effective_budget": effective}}

    # The serialized state size differs with its timing figures: not a behaviour difference.
    assert _compare(
        _with_status(_make_run(1), budget(1048576, 34784)),
        _with_status(_make_run(2), budget(1048576, 34790)),
    )["identical"]
    # Probe P3: a different configured limit is.
    result = _compare(
        _with_status(_make_run(1), budget(1048576, 34784)),
        _with_status(_make_run(2), budget(2097152, 34784)),
    )
    assert not result["identical"]
    assert result["workspaces"]["w"]["mismatches"][0]["path"] == (
        "/selection/effective_budget/limits/state_bytes"
    )


def test_a_lock_timeout_row_is_compared_while_a_long_hold_row_is_not() -> None:
    long_hold = {
        "event": "PostToolUse",
        "holder_held_ms": 1200,
        "kind": "store_lock",
        "phase": "capture",
        "reason": "store_lock_long_hold",
        "role": "hook",
        "ts": "2026-10-16T20:00:02.000000Z",
    }
    timeout = {
        **long_hold,
        "holder_held_ms": 2100,
        "holder_phase": "drain",
        "holder_role": "service",
        "holder_waiting": False,
        "reason": "store_lock_timeout",
        "scope": "process",
        "waited_ms": 2000,
    }

    def locks(*rows: dict[str, Any]) -> dict[str, Any]:
        return {"hook_diagnostics": {"store_lock_events": list(rows)}}

    assert _compare(
        _with_status(_make_run(1), locks()), _with_status(_make_run(2), locks(long_hold))
    )["identical"]
    assert _compare(
        _with_status(_make_run(1), locks(timeout)),
        _with_status(_make_run(2), locks({**timeout, "holder_held_ms": 2500, "waited_ms": 2001})),
    )["identical"]
    # Probe P8: a lock timeout in one run only.
    result = _compare(
        _with_status(_make_run(1), locks()), _with_status(_make_run(2), locks(timeout))
    )
    assert not result["identical"]


def test_session_boundary_timing_rows_are_counted_and_only_their_milliseconds_dropped() -> None:
    def timings(count: int, ms: int) -> dict[str, Any]:
        row: dict[str, Any] = {
            "count": count,
            "last_ms": ms,
            "max_ms": ms,
            "recent_count": count,
            "paths": {},
        }
        return {"hook_diagnostics": {"timings": row}}

    assert _compare(
        _with_status(_make_run(1), timings(3, 900)), _with_status(_make_run(2), timings(3, 950))
    )["identical"]
    assert not _compare(
        _with_status(_make_run(1), timings(3, 900)), _with_status(_make_run(2), timings(4, 900))
    )["identical"]
    assert _MODULE.PINNED_HOOK_BUDGETS["_HOOK_TOTAL_BUDGET_SECONDS"] >= 120.0


def test_an_advice_ranking_is_compared_by_position() -> None:
    # Probe P1: the same three findings, ranked second and third the other way round.
    def ranked(seed: int, swap: bool) -> dict[str, Any]:
        run = _make_run(seed)
        status = json.loads(run["ledgers"]["w"]["observe_status"])
        gen = _Gen(seed + 50)
        second, third = gen.id("fnd"), gen.id("fnd")
        top = status["advice"]["finding_ids"][0]
        status["advice"]["finding_ids"] = [top, third, second] if swap else [top, second, third]
        status["failures"] = {"first": second, "second": third}
        return _with_status(run, status)

    assert _compare(ranked(1, False), ranked(2, False))["identical"]
    result = _compare(ranked(1, False), ranked(2, True))
    assert not result["identical"]


def test_an_insertion_ordered_identifier_list_is_compared_by_position() -> None:
    # Probe P5: a list no producer sorts, whose order flips between the runs.
    def related(flip: bool) -> Callable[[str, dict[str, Any], _Gen], None]:
        def hook(name: str, payload: dict[str, Any], gen: _Gen) -> None:
            if name == "finding_recorded":
                first, second = gen.id("evd"), gen.id("evd")
                payload["related_refs"] = [second, first] if flip else [first, second]
                payload["first_ref"] = first

        return hook

    assert _compare(
        _make_run(1, payload_hook=related(False)), _make_run(2, payload_hook=related(False))
    )["identical"]
    result = _compare(
        _make_run(1, payload_hook=related(False)), _make_run(2, payload_hook=related(True))
    )
    assert not result["identical"]
    assert [m["part"] for m in result["workspaces"]["w"]["mismatches"]] == ["w event[5] payload"]


def test_a_set_path_out_of_its_producer_order_is_compared_by_position() -> None:
    # ``result_recorded.evidence_refs`` is sorted by its producer; a list there that is not sorted
    # was not made by that producer, so its order is compared.
    def refs(order: str) -> Callable[[str, dict[str, Any], _Gen], None]:
        def hook(name: str, payload: dict[str, Any], gen: _Gen) -> None:
            if name == "result_recorded":
                pair = sorted([gen.id("evd"), gen.id("evd")])
                payload["evidence_refs"] = pair if order == "sorted" else pair[::-1]
                payload["first_ref"] = pair[0]

        return hook

    for seed in range(2, 12):
        assert _compare(
            _make_run(1, payload_hook=refs("sorted")), _make_run(seed, payload_hook=refs("sorted"))
        )["identical"]
    assert not _compare(
        _make_run(1, payload_hook=refs("sorted")), _make_run(2, payload_hook=refs("reversed"))
    )["identical"]


def test_seeded_runs_keep_observation_keyed_values_exact() -> None:
    # Probe P4: under one shared observation key a source identity is deterministic, so a
    # different one in the same place is a difference, not a renaming.
    old, new = _make_run(1), _make_run(2)
    new = json.loads(json.dumps(new).replace(_HOOK_IDENTITY, "hook:" + "e" * 48))
    result = _compare(old, new)
    assert not result["identical"]
    assert (
        result["workspaces"]["w"]["mismatches"][0]["part"] == "codex/w/001/PostToolUse/Bash stdout"
    )
    # A keyed command commitment the same way.
    other = _Gen(4).keyed()

    def recommit(name: str, payload: dict[str, Any], _gen: _Gen) -> None:
        if name == "action_recorded":
            parts = cast(str, payload["command"]).split(" ")
            payload["command"] = " ".join(["omitted:" + other, *parts[1:]])

    assert not _compare(_make_run(1), _make_run(2, payload_hook=recommit))["identical"]
    # Without the shared key the same values are per-instance and are renamed.
    unseeded_old, unseeded_new = _make_run(1, seeded=False), _make_run(2, seeded=False)
    assert _compare(unseeded_old, unseeded_new)["identical"]
    unseeded_new = json.loads(json.dumps(unseeded_new).replace(_HOOK_IDENTITY, "hook:" + "e" * 48))
    assert _compare(unseeded_old, unseeded_new)["identical"]
    # Vault-keyed payload commitments differ in every pair of seeded runs and stay renamed.
    entries = [json.loads(e["canonical_entry"]) for e in old["export"]["tasks"][0]["events"]]
    assert {entry["payload_ref"]["commitment"] for entry in entries} == set(
        _MODULE.vault_keyed_values(old)
    )


def _replace_advice_finding(run: dict[str, Any], other: str) -> dict[str, Any]:
    """Put ``other`` in both places the run's advice finding id occurs, keeping digests valid."""

    finding = json.loads(run["export"]["tasks"][0]["events"][4]["payload"])["finding_id"]
    _rewrite_payload(run, 4, {"finding_id": other})
    status = json.loads(run["ledgers"]["w"]["observe_status"])
    assert status["advice"]["finding_ids"] == [finding]
    return _with_status(run, {"advice": {**status["advice"], "finding_ids": [other]}})


def test_seeded_runs_keep_the_advice_finding_id_exact() -> None:
    # Probe P9: a build that derived another advice finding id, in the same two places (the
    # ``finding_recorded`` payload and the observe-status ranking), is a difference.
    old, new = _make_run(1), _make_run(2)
    assert _MODULE.advice_finding_ids(old) == _MODULE.advice_finding_ids(new)
    assert _compare(old, new)["identical"]
    new = _replace_advice_finding(new, "fnd_00000000-0000-4000-8000-000000000001")
    assert _MODULE.run_failures(new) == []
    result = _compare(old, new)
    assert not result["identical"]
    assert [m["part"] for m in result["workspaces"]["w"]["mismatches"]] == [
        "w observe status",
        "w event[5] payload",
    ]
    # Without the shared key the id is per-instance and is renamed by where it occurs.
    unseeded_old, unseeded_new = _make_run(1, seeded=False), _make_run(2, seeded=False)
    unseeded_new = _replace_advice_finding(unseeded_new, "fnd_00000000-0000-4000-8000-000000000001")
    assert _compare(unseeded_old, unseeded_new)["identical"]


def test_a_renamed_value_equal_in_both_seeded_runs_fails() -> None:
    # A deterministic value the comparison renames would hide a difference in it, so in seeded runs,
    # where no run-generated value repeats, one that is the same in both runs fails the comparison.
    fixed = "evd_00000000-0000-4000-8000-0000000000aa"

    def cite(name: str, payload: dict[str, Any], _gen: _Gen) -> None:
        if name == "finding_recorded":
            payload["related_ref"] = fixed

    result = _compare(_make_run(1, payload_hook=cite), _make_run(2, payload_hook=cite))
    assert all(entry["identical"] for entry in result["workspaces"].values())
    assert result["bijection"]["consistent"]
    assert not result["identical"]
    assert result["renamed_equal"] == [fixed]
    assert result["renamed_equal_count"] == 1
    report, _ = _MODULE.render_report(
        _record(_make_run(1, payload_hook=cite, catalog="eager"), "old"),
        _record(_make_run(2, payload_hook=cite), "new"),
    )
    assert "Verdict (pinned runs only): **DIFFERENT**." in report
    assert (
        f"Renamed values equal in both runs (seeded runs must have none): 1.\n- `{fixed}`" in report
    )
    # Unseeded runs keep observation-keyed values renamed, and one without keyed inputs may repeat.
    assert _compare(
        _make_run(1, payload_hook=cite, seeded=False), _make_run(2, payload_hook=cite, seeded=False)
    )["identical"]


def test_runs_under_different_controls_or_an_unwritten_seed_are_refused() -> None:
    old, new = _make_run(1), _make_run(2)
    new["controls"]["admission_clock"] = "held"
    assert _compare(old, new)["refused"]["new"] == [
        "controls_differ:{'fixed_observation_key': True, 'admission_clock': 'held'}"
    ]
    old, new = _make_run(1), _make_run(2, seeded=False)
    assert "refused" in _compare(old, new)
    old, new = _make_run(1), _make_run(2)
    new["controls"]["observation_key_seeded"] = False
    assert _compare(old, new)["refused"]["new"] == ["observation_key_not_seeded"]
    del new["controls"]
    assert _compare(old, new)["refused"]["new"] == ["controls_missing"]


def test_captured_evidence_in_random_object_order_is_compared_as_a_multiset() -> None:
    # The tool input and output evidence of one call are emitted in random ``obj_`` order, so two
    # runs of one build put them in either order; their contents are still compared in full.
    old = _make_run(1, captured="input-first")
    assert _MODULE.captured_evidence_groups(old["export"]["tasks"][0]) == [(4, 5)]
    same = _compare(old, _make_run(2, captured="input-first"))
    assert same["identical"], same
    swapped = _compare(old, _make_run(2, captured="output-first"))
    assert swapped["identical"], swapped
    assert swapped["workspaces"]["w"]["events"] == 7


def test_a_real_difference_inside_a_captured_group_is_not_hidden() -> None:
    old = _make_run(1, captured="input-first")

    def digest(name: str, payload: dict[str, Any], _gen: _Gen) -> None:
        if "tool_output" in cast(str, payload.get("description", "")):
            payload["content_digest"] = "sha256:" + "3" * 64

    result = _compare(old, _make_run(2, captured="output-first", payload_hook=digest))
    assert not result["identical"]
    parts = [m["part"] for m in result["workspaces"]["w"]["mismatches"]]
    assert parts == ["w event[4-5] captured[1] payload"]

    # Captured evidence accepted at different times is no such group and is compared by position.
    apart = _make_run(2, captured="apart")
    assert _MODULE.captured_evidence_groups(apart["export"]["tasks"][0]) == []
    assert _compare(_make_run(1, captured="apart"), apart)["identical"]
    assert not _compare(old, apart)["identical"]


def test_a_captured_group_still_needs_an_intact_hash_chain() -> None:
    old, new = _make_run(1, captured="input-first"), _make_run(2, captured="output-first")
    event = new["export"]["tasks"][0]["events"][3]
    event["canonical_entry"] = event["canonical_entry"].replace("hook_observed", "local_cli", 1)
    result = _compare(old, new)
    assert not result["identical"]
    assert result["refused"]["new"]


def _record(run: dict[str, Any], ref: str) -> dict[str, Any]:
    corpus: dict[str, Any] = {"sha256": "sha256:" + "1" * 64, "generated_tokens": []}
    return {"corpus": corpus, "runs": {"pinned": run}, "build": {"source_ref": ref}}


def test_the_proof_requires_the_new_build_to_take_the_lazy_path() -> None:
    eager, lazy = _make_run(1, catalog="eager"), _make_run(2)
    summary = _MODULE.compare_records(_record(eager, "old"), _record(lazy, "new"))
    assert summary["identical"], summary
    assert summary["lazy_catalog"] == {
        "valid": 3,
        "lazy": 3,
        "no_schemas": 0,
        "new_full": 0,
        "old_full": 3,
        "lazy_documents": [92],
    }
    report, _ = _MODULE.render_report(_record(eager, "old"), _record(lazy, "new"))
    assert "3 parsed only their schemas (lazy documents: 92)" in report
    # Two eager builds compare equal and still prove nothing about lazy loading.
    summary = _MODULE.compare_records(
        _record(eager, "old"), _record(_make_run(2, catalog="eager"), "new")
    )
    assert not summary["identical"]
    assert "lazy_path_unexercised" in summary["failures"]
    assert "full_catalog_built_in_new:codex/w/000/SessionStart" in summary["failures"]
    # A callback that loaded schemas before and none now did not take the lazy path.
    skipped = _make_run(2)
    skipped["items"][1]["catalog_trace"] = [{"full_catalog_built": False, "lazy_documents": None}]
    summary = _MODULE.compare_records(_record(eager, "old"), _record(skipped, "new"))
    assert summary["failures"] == ["lazy_path_not_taken:codex/w/001/PostToolUse/Bash"]
    # A missing trace is a failed read, never an empty one.
    del skipped["items"][1]["catalog_trace"]
    summary = _MODULE.compare_records(_record(eager, "old"), _record(skipped, "new"))
    assert summary["failures"] == ["catalog_trace_missing:codex/w/001/PostToolUse/Bash"]


def test_runs_from_two_work_roots_are_refused_with_the_cause() -> None:
    old, new = _make_run(1), _make_run(2)
    new["workspace_root"] = "/elsewhere/pinned"
    refused = _compare(old, new)["refused"]
    assert refused["new"] == [
        "workspace_roots_differ:/elsewhere/pinned (replay both builds with one --work-root)"
    ]
    del new["workspace_root"]
    assert _compare(old, new)["refused"]["new"] == ["workspace_root_missing"]


def test_only_the_pinned_runs_decide_the_verdict() -> None:
    old, new = _record(_make_run(1, catalog="eager"), "old"), _record(_make_run(2), "new")
    # A shipped run that differs is timed, never compared.
    old["runs"]["shipped"] = _make_run(3, catalog="eager")
    new["runs"]["shipped"] = _make_run(4, outcome="success")
    summary = _MODULE.compare_records(old, new)
    assert summary["identical"], summary
    assert set(summary["modes"]) == {"pinned"}
    assert summary["latency_only"]["shipped"]
    report, _ = _MODULE.render_report(old, new)
    assert "Verdict (pinned runs only): **IDENTICAL**." in report
    assert "## Mode `shipped`: latency only, not compared" in report
    # Without pinned runs there is no verdict to give.
    del old["runs"]["pinned"], new["runs"]["pinned"]
    summary = _MODULE.compare_records(old, new)
    assert not summary["identical"]
    assert summary["failures"] == ["pinned_run_missing:['shipped']:['shipped']"]


def test_the_mcp_bridge_keeps_the_full_catalog_so_the_replay_need_not_drive_it() -> None:
    # The runbooks leave the bridge out of the replay because lazy loading never reaches it: its
    # tool descriptors are generated from the full catalog when the bridge module loads.
    probe = (
        "import json, sys\n"
        "from finishup.protocol import schemas\n"
        "before = schemas._load_catalog_state.cache_info().currsize\n"
        "import finishup.mcp.server\n"
        "after = schemas._load_catalog_state.cache_info().currsize\n"
        "try:\n"
        "    schemas.validate_schema_instance('status-request', sys.argv[1], {})\n"
        "except schemas.SchemaInstanceInvalid:\n"
        "    pass\n"
        "print(json.dumps([before, after, len(schemas._lazy_catalog_slot)]))\n"
    )
    version = _MODULE._PROBE_VERSIONS["status-request"]
    done = subprocess.run(
        [sys.executable, "-I", "-c", probe, version], capture_output=True, check=True
    )
    # No catalog before the import, the full catalog right after it, and never a lazy one.
    assert json.loads(done.stdout) == [0, 1, 0]
