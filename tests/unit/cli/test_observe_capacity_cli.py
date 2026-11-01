"""Owner capacity choices on the CLI: custom counts, disclosure, and the no-cap outcome (#828)."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, Final, cast

import pytest
from typer.testing import CliRunner, Result

from finishup.adapters.integrations.codex_lifecycle import LifecycleMapping, store_mapping
from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    ObservationOutboxRow,
)
from finishup.cli import observe as observe_cli
from finishup.cli.app import app
from finishup.cli.exits import exit_code_for
from finishup.cli.observe import (
    CapacityNoCapUnsupported,
    apply_selection_preview,
    build_selection_preview,
)
from finishup.domain.observation import ObservationCursor, ObservationEnvelope, ObservationSource
from finishup.domain.observation_budget import (
    ObservationCapacity,
    ObservationMode,
    no_cap_support,
    parse_capacity_request,
)
from finishup.domain.observation_capacity_policy import render_capacity_disclosure_lines
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.recovery import RECOVERY_DIRECTIVES

TASK = "tsk_17607d01-2f55-4b28-82b6-8659242a1267"
SESSION = "ses_6201a23d-a03a-46a5-bda9-d16a7a261ee0"
WRITER = "wri_45c1a9bb-20ac-41ce-9fb9-19394f76e1e1"
HOST = "codex-observation-capacity-test"
INVALID_REQUEST_EXIT = exit_code_for(PublicErrorCode.INVALID_REQUEST)
NO_CAP_SENTENCE = "No FinishUP cap is not available"
INCREASE_SENTENCE = "Larger local retention can increase disk use"
DECREASE_SENTENCE = "Lowering affects future admission only"

type Json = dict[str, Any]


class Env:
    """One isolated observation store reachable through the real Typer commands."""

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.workspace = tmp_path / "workspace"
        self.workspace.mkdir()
        self.root = tmp_path / "isolated"
        self.store = LocalObservationStore(_state=self.root)
        self.commitment = self.store.workspace_commitment(str(self.workspace.resolve()))
        self.store.grant_consent(self.commitment)
        self.session = self.store.bind_codex_session(self.commitment, HOST)
        store_mapping(LifecycleMapping(1, HOST, TASK, SESSION, WRITER, None), _state=self.root)
        root = self.root

        def isolated_store(*, _state: Path | None = None) -> LocalObservationStore:
            del _state
            return LocalObservationStore(_state=root)

        # The commands open their store with the default state root; every
        # invocation here is redirected to this test's isolated root.
        monkeypatch.setattr(observe_cli, "LocalObservationStore", isolated_store)
        self.runner = CliRunner()

    def invoke(self, command: str, *args: str) -> Result:
        return self.runner.invoke(
            app,
            ["observe", command, "--workspace", str(self.workspace), *args],
        )

    def json(self, command: str, *args: str, exit_code: int = 0) -> Json:
        result = self.invoke(command, *args, "--json")
        assert result.exit_code == exit_code, (result.stdout, result.stderr)
        lines = result.stdout.splitlines()
        assert len(lines) == 1, result.stdout
        return cast(Json, json.loads(lines[0]))

    def preview(self, *args: str) -> Json:
        return self.json("selection-preview", "--detail", "focused", *args)

    def apply(self, *args: str, digest: str) -> Json:
        return self.json(
            "selection-apply",
            "--detail",
            "focused",
            *args,
            "--accept",
            "--preview-digest",
            digest,
        )

    def preview_and_apply(self, *args: str) -> Json:
        return self.apply(*args, digest=self.preview(*args)["preview_digest"])

    def workspace_queue_count(self) -> int | None:
        setting = (
            LocalObservationStore(_state=self.root)
            .selection_settings_for(self.commitment)
            .workspace
        )
        return None if setting is None else setting.selection.capacity.queue_count


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    yield Env(tmp_path, monkeypatch)


_ANSI: Final = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _flat(text: str) -> str:
    # Rich colors the help on a color-capable CI runner, splitting option names
    # across escape sequences; strip them before matching the words.
    plain = _ANSI.sub("", text)
    return re.sub(r"\s+", " ", re.sub(r"[│╭╮╰╯─]", " ", plain))


def test_capacity_help_lists_every_choice_and_queue_count() -> None:
    for command in ("selection-preview", "selection-apply"):
        result = CliRunner().invoke(app, ["observe", command, "--help"], terminal_width=200)
        assert result.exit_code == 0
        text = _flat(result.stdout)
        assert "--queue-count" in text
        for phrase in (
            "standard (recommended, 512)",
            "larger (2048)",
            "largest (8192)",
            "custom (with --queue-count 64..8192)",
            "none (no FinishUP cap; reports why it is unavailable)",
        ):
            assert phrase in text, phrase


def test_custom_preview_discloses_the_increase(env: Env) -> None:
    payload = env.preview("--capacity", "custom", "--queue-count", "1024", "--persist")

    assert payload["schema"] == "yoetz.observation-selection-preview/2"
    assert payload["capacity_request"] == {"kind": "custom", "queue_count": 1024}
    assert payload["requested_selection"]["capacity_profile"] == "custom"
    assert payload["requested_selection"]["capacity"] == 1024
    assert payload["requested_selection"]["queue_count"] == 1024
    assert payload["aggregate_capacity"] == 1024
    assert payload["aggregate_capacity_profile"] == "custom"
    disclosure = payload["disclosure"]
    assert disclosure["schema"] == "yoetz.capacity-change-disclosure/1"
    assert disclosure["change"] == "increase"
    assert disclosure["scope"] == "workspace"
    assert disclosure["current"]["queue_count"] == 512
    assert disclosure["requested"] == {
        "queue_count": 1024,
        "label": "custom",
        "queue_bytes_limit": 1024 * 1024,
        "state_bytes_limit": 2 * 1024 * 1024,
    }
    assert disclosure["consequences"] == [
        "disk_use",
        "memory_use",
        "cpu_work",
        "host_slowdown_possible",
        "workspace_aggregate_raised",
    ]
    assert disclosure["remaining_limits"]["pending_attempts"] == 256
    assert disclosure["remaining_limits"]["capture_tickets"] == 512
    assert disclosure["remaining_limits"]["state_document_ceiling_bytes"] == 16 * 1024 * 1024
    assert disclosure["no_cap"] == dict(no_cap_support())
    assert disclosure["lower_command"].startswith(
        "finishup observe selection-preview --workspace <workspace> --detail focused "
        "--capacity standard --persist then finishup observe selection-apply"
    )
    assert disclosure["pause_command"] == "finishup observe pause --workspace <workspace>"
    assert disclosure["resume_command"] == "finishup observe resume --workspace <workspace>"
    assert disclosure["revoke_command"] == (
        "finishup observe selection-revoke --workspace <workspace> --persist"
    )
    assert payload["current_effective_budget"]["schema"] == "yoetz.observation-effective-budget/1"
    assert payload["current_effective_budget"]["selected_queue_count"] == 512
    assert payload["next_command"] == (
        "finishup observe selection-apply --workspace <workspace> --detail focused "
        "--capacity custom --queue-count 1024 --persist "
        f"--accept --preview-digest {payload['preview_digest']}"
    )
    # A preview changes nothing.
    assert env.workspace_queue_count() is None

    human = env.invoke(
        "selection-preview",
        "--detail",
        "focused",
        "--capacity",
        "custom",
        "--queue-count",
        "1024",
        "--persist",
    )
    assert human.exit_code == 0
    assert INCREASE_SENTENCE in human.stdout
    assert "Scope: this workspace. Queue: 512 → 1,024 rows" in human.stdout
    assert (
        "The shared workspace queue follows the largest active selection, so this can raise "
        "the queue and state-document bounds for every session in the workspace."
    ) in human.stdout
    assert (
        "Pause new observation ingest with: finishup observe pause --workspace <workspace>."
        in human.stdout
    )
    assert "Resume with: finishup observe resume --workspace <workspace>." in human.stdout
    assert "preview_digest: " in human.stdout
    # Structured records are summarized, never dumped as a mapping repr.
    assert "\ndisclosure: " not in human.stdout
    assert "current_effective_budget: " not in human.stdout
    assert "effective_budget:selected=512(standard); effective=512(standard)" in human.stdout
    # The caller's workspace path is never echoed into a command.
    assert str(env.workspace) not in human.stdout


def test_apply_with_the_digest_persists_a_custom_count(env: Env) -> None:
    applied = env.preview_and_apply("--capacity", "custom", "--queue-count", "1024", "--persist")

    assert applied["applied"] is True
    assert applied["selection"]["capacity_profile"] == "custom"
    assert applied["selection"]["queue_count"] == 1024
    assert applied["disclosure"]["change"] == "increase"
    assert applied["effective_budget"]["selected_queue_count"] == 1024
    assert applied["effective_budget"]["selected_capacity_label"] == "custom"
    assert env.workspace_queue_count() == 1024

    status = env.json("selection-status")
    budget = status["effective_budget"]
    assert budget["selected_queue_count"] == 1024
    assert budget["selected_capacity_label"] == "custom"
    assert budget["effective_queue_count"] == 1024
    assert budget["limits"]["queue_count"] == 1024
    assert status["selected"]["capacity_profile"] == "custom"
    assert status["selected"]["queue_count"] == 1024

    human_status = env.invoke("selection-status")
    assert human_status.exit_code == 0
    assert "selected=focused/custom" in human_status.stdout
    assert (
        "effective_budget:selected=1024(custom); effective=1024(custom); reason=selected; "
        in human_status.stdout
    )
    assert "no_cap=unavailable(state_document_ceiling); " in human_status.stdout
    assert "lower=finishup observe selection-revoke or selection-apply --capacity standard; " in (
        human_status.stdout
    )
    assert "pause=finishup observe pause" in human_status.stdout


def test_human_apply_reports_the_effective_budget_and_the_way_back(env: Env) -> None:
    args = ("--detail", "focused", "--capacity", "custom", "--queue-count", "1024", "--persist")
    digest = env.preview(*args[2:])["preview_digest"]
    result = env.invoke("selection-apply", *args, "--accept", "--preview-digest", digest)

    assert result.exit_code == 0, result.stderr
    assert (
        "observation_selection_applied:scope=workspace; detail=focused; capacity=custom(1024)"
        in (result.stdout)
    )
    assert "effective_budget:selected=1024(custom); effective=1024(custom)" in result.stdout
    assert "Lower it later with: finishup observe selection-preview" in result.stdout
    assert (
        "Pause new observation ingest with: finishup observe pause --workspace <workspace>."
        in result.stdout
    )
    assert "Resume with: finishup observe resume --workspace <workspace>." in result.stdout
    assert "effective_budget: {" not in result.stdout


def test_decrease_discloses_future_admission_only(env: Env) -> None:
    env.preview_and_apply("--capacity", "larger", "--persist")
    assert env.workspace_queue_count() == 2048

    payload = env.preview("--capacity", "custom", "--queue-count", "128", "--persist")
    assert payload["disclosure"]["change"] == "decrease"
    assert payload["disclosure"]["consequences"] == [
        "future_admission_only",
        "accepted_records_drain",
    ]
    assert payload["disclosure"]["current"]["queue_count"] == 2048
    assert payload["disclosure"]["requested"]["queue_count"] == 128

    human = env.invoke(
        "selection-preview",
        "--detail",
        "focused",
        "--capacity",
        "custom",
        "--queue-count",
        "128",
        "--persist",
    )
    assert human.exit_code == 0
    assert DECREASE_SENTENCE in human.stdout
    assert INCREASE_SENTENCE not in human.stdout

    result = env.invoke(
        "selection-apply",
        "--detail",
        "focused",
        "--capacity",
        "custom",
        "--queue-count",
        "128",
        "--persist",
        "--accept",
        "--preview-digest",
        payload["preview_digest"],
    )
    assert result.exit_code == 0, result.stderr
    assert "capacity=custom(128)" in result.stdout
    assert (
        "Revoke it with: finishup observe selection-revoke --workspace <workspace> --persist. "
        "Pause new observation ingest with: finishup observe pause --workspace <workspace>."
    ) in result.stdout
    assert "Resume with: finishup observe resume --workspace <workspace>." in result.stdout
    assert env.workspace_queue_count() == 128


def test_lowering_after_a_custom_increase_restores_the_previous_count(env: Env) -> None:
    env.preview_and_apply("--capacity", "custom", "--queue-count", "64", "--persist")
    raised = env.preview_and_apply("--capacity", "custom", "--queue-count", "128", "--persist")
    assert env.workspace_queue_count() == 128
    assert "--capacity custom --queue-count 64 --persist" in raised["disclosure"]["lower_command"]
    restore = env.preview("--capacity", "custom", "--queue-count", "64", "--persist")
    assert restore["disclosure"]["change"] == "decrease"
    env.apply(
        "--capacity", "custom", "--queue-count", "64", "--persist", digest=restore["preview_digest"]
    )
    assert env.workspace_queue_count() == 64


def _assert_no_cap_json(payload: Json, operation: str, alternative: str) -> None:
    assert set(payload) == {"error"}
    error = payload["error"]
    assert error["code"] == "INVALID_REQUEST"
    assert error["reason"] == "capacity_no_cap_unsupported"
    assert error["operation"] == operation
    assert error["retryable"] is False
    assert error["message"].startswith(NO_CAP_SENTENCE)
    # ADR-030: ``recovery`` carries the typed continuation; the capacity facts sit beside it.
    recovery = error["recovery"]
    assert recovery["continuation"] == "capacity_request_correction"
    assert recovery["directive"] == RECOVERY_DIRECTIVES["capacity_request_correction"].directive
    assert "no_cap" not in recovery
    assert "alternative_command" not in recovery
    assert error["capacity"] == {
        "no_cap": {
            "available": False,
            "dimension": "structural_queue",
            "reason": "state_document_ceiling",
            "state_document_ceiling_bytes": 16 * 1024 * 1024,
            "largest_supported_queue_count": 8192,
        },
        "alternative_command": alternative,
    }


@pytest.mark.parametrize("word", ["none", "unlimited", "No-Cap"])
def test_no_cap_is_a_typed_outcome_on_preview_and_apply(env: Env, word: str) -> None:
    alternative = (
        "finishup observe selection-preview --workspace <workspace> "
        "--detail focused --capacity largest --persist"
    )
    preview = env.json(
        "selection-preview",
        "--detail",
        "focused",
        "--capacity",
        word,
        "--persist",
        exit_code=INVALID_REQUEST_EXIT,
    )
    _assert_no_cap_json(preview, "selection_preview", alternative)
    applied = env.json(
        "selection-apply",
        "--detail",
        "focused",
        "--capacity",
        word,
        "--persist",
        "--accept",
        "--preview-digest",
        "0" * 64,
        exit_code=INVALID_REQUEST_EXIT,
    )
    _assert_no_cap_json(applied, "selection_apply", alternative)
    assert env.workspace_queue_count() is None

    for command, extra in (
        ("selection-preview", ()),
        ("selection-apply", ("--accept", "--preview-digest", "0" * 64)),
    ):
        human = env.invoke(command, "--detail", "focused", "--capacity", word, "--persist", *extra)
        assert human.exit_code == INVALID_REQUEST_EXIT
        assert human.stdout == ""
        assert "capacity_no_cap_unsupported: No FinishUP cap is not available" in human.stderr
        assert "16 MiB safety ceiling" in human.stderr
        assert f"Alternative: {alternative}" in human.stderr
        assert "Continuation: capacity_request_correction" in human.stderr
        assert str(env.workspace) not in human.stderr
        # The explanation is printed once, not repeated as a directive line.
        assert human.stderr.count(NO_CAP_SENTENCE) == 1


def test_no_cap_for_a_session_names_the_session_alternative(env: Env) -> None:
    payload = env.json(
        "selection-preview",
        "--detail",
        "detailed",
        "--capacity",
        "none",
        "--session-id",
        HOST,
        exit_code=INVALID_REQUEST_EXIT,
    )
    assert payload["error"]["capacity"]["alternative_command"] == (
        "finishup observe selection-preview --workspace <workspace> "
        "--detail detailed --capacity largest --session-id <session-id>"
    )


def test_failure_json_carries_no_disclosure_sentences(env: Env) -> None:
    result = env.invoke(
        "selection-preview", "--detail", "focused", "--capacity", "none", "--persist", "--json"
    )
    assert result.exit_code == INVALID_REQUEST_EXIT
    assert result.stderr == ""
    for sentence in (INCREASE_SENTENCE, DECREASE_SENTENCE, "Alternative:", "Still limited"):
        assert sentence not in result.stdout
    assert len(result.stdout.splitlines()) == 1


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (
            ("--capacity", "custom"),
            "A custom capacity needs --queue-count between 64 and 8,192.",
        ),
        (
            ("--capacity", "custom", "--queue-count", "8193"),
            "The queue count must be between 64 and 8,192 rows.",
        ),
        (
            ("--capacity", "custom", "--queue-count", "63"),
            "The queue count must be between 64 and 8,192 rows.",
        ),
        (("--capacity", "9000"), "The queue count must be between 64 and 8,192 rows."),
        (
            ("--capacity", "standard", "--queue-count", "1024"),
            "--queue-count is only used with --capacity custom.",
        ),
        (
            ("--capacity", "huge"),
            "Capacity must be standard (recommended), larger, largest, custom with "
            "--queue-count, or none.",
        ),
    ],
)
def test_invalid_capacity_requests_are_invalid_request(
    env: Env, args: Sequence[str], message: str
) -> None:
    for command in ("selection-preview", "selection-apply"):
        payload = env.json(
            command,
            "--detail",
            "focused",
            *args,
            "--persist",
            exit_code=INVALID_REQUEST_EXIT,
        )
        assert payload["error"]["code"] == "INVALID_REQUEST"
        assert payload["error"]["reason"] == "invalid_request"
        assert payload["error"]["message"] == message
    assert env.workspace_queue_count() is None


def test_stale_digest_and_missing_accept_are_still_refused(env: Env) -> None:
    digest = env.preview("--capacity", "custom", "--queue-count", "1024", "--persist")[
        "preview_digest"
    ]
    stale = env.json(
        "selection-apply",
        "--detail",
        "focused",
        "--capacity",
        "custom",
        "--queue-count",
        "2000",
        "--persist",
        "--accept",
        "--preview-digest",
        digest,
        exit_code=INVALID_REQUEST_EXIT,
    )
    assert "preview is stale" in stale["error"]["message"]
    missing_accept = env.json(
        "selection-apply",
        "--detail",
        "focused",
        "--capacity",
        "custom",
        "--queue-count",
        "1024",
        "--persist",
        "--preview-digest",
        digest,
        exit_code=INVALID_REQUEST_EXIT,
    )
    assert "--accept" in missing_accept["error"]["message"]
    assert env.workspace_queue_count() is None


def test_recommended_is_standard_and_a_bare_count_is_its_profile(env: Env) -> None:
    standard = env.preview("--capacity", "standard", "--persist")
    recommended = env.preview("--capacity", "Recommended", "--persist")
    assert recommended["preview_digest"] == standard["preview_digest"]
    assert recommended["capacity_request"] == {"kind": "profile", "queue_count": 512}
    assert recommended["disclosure"]["change"] == "unchanged"

    larger = env.preview("--capacity", "larger", "--persist")
    bare = env.preview("--capacity", "2048", "--persist")
    assert bare["preview_digest"] == larger["preview_digest"]
    assert bare["capacity_request"] == {"kind": "profile", "queue_count": 2048}
    assert bare["requested_selection"]["capacity_profile"] == "larger"
    assert "--capacity larger --persist" in bare["next_command"]

    # The digest from one spelling applies under the other.
    env.apply("--capacity", "2048", "--persist", digest=larger["preview_digest"])
    assert env.workspace_queue_count() == 2048


def test_revoke_restores_the_default_after_a_custom_count(env: Env) -> None:
    env.preview_and_apply("--capacity", "custom", "--queue-count", "1024", "--persist")
    revoked = env.json("selection-revoke", "--persist")
    assert revoked["revoked"] is True
    assert revoked["fallback"]["capacity"] == 512
    assert revoked["fallback"]["capacity_profile"] == "standard"
    assert env.workspace_queue_count() is None


def test_session_custom_count_reports_a_session_budget(env: Env) -> None:
    env.preview_and_apply("--capacity", "custom", "--queue-count", "1500", "--session-id", HOST)
    status = env.json("selection-status", "--session-id", HOST)
    assert status["effective_budget"]["scope"] == "session"
    assert status["effective_budget"]["selected_queue_count"] == 1500
    assert status["effective_budget"]["selected_capacity_label"] == "custom"
    assert env.workspace_queue_count() is None


def test_shared_functions_raise_the_typed_no_cap_outcome(env: Env) -> None:
    with pytest.raises(CapacityNoCapUnsupported) as raised:
        build_selection_preview(
            env.store,
            env.commitment,
            detail=ObservationMode.FOCUSED,
            capacity=parse_capacity_request("none"),
            scope="workspace",
            session_commitment=None,
            expires_at=None,
        )
    outcome = raised.value
    assert isinstance(outcome, PublicOperationError)
    assert outcome.code is PublicErrorCode.INVALID_REQUEST
    assert outcome.retryable is False
    assert outcome.no_cap == no_cap_support()
    assert outcome.disclosure["change"] == "unsupported"
    assert outcome.lines == render_capacity_disclosure_lines(outcome.disclosure)
    assert outcome.message == outcome.lines[0]
    assert outcome.alternative_command == (
        "finishup observe selection-preview --workspace <workspace> "
        "--detail focused --capacity largest --persist"
    )
    with pytest.raises(CapacityNoCapUnsupported):
        apply_selection_preview(
            env.store,
            env.commitment,
            detail=ObservationMode.FOCUSED,
            capacity=parse_capacity_request("none"),
            scope="workspace",
            session_commitment=None,
            expires_at=None,
            preview_digest="0" * 64,
            accept=True,
        )


def test_shared_functions_preview_then_apply_a_custom_count(env: Env) -> None:
    request = parse_capacity_request("custom", queue_count=3000)
    preview = build_selection_preview(
        env.store,
        env.commitment,
        detail=ObservationMode.DETAILED,
        capacity=request,
        scope="workspace",
        session_commitment=None,
        expires_at=None,
    )
    assert preview["preview"] is True
    assert preview["apply_requires_owner"] is True
    assert preview["capacity_validation"] == "provisional"
    assert preview["acceptance"] == "explicit_preview_digest"
    assert "--capacity custom --queue-count 3000" in str(preview["next_command"])

    with pytest.raises(PublicOperationError) as refused:
        apply_selection_preview(
            env.store,
            env.commitment,
            detail=ObservationMode.DETAILED,
            capacity=request,
            scope="workspace",
            session_commitment=None,
            expires_at=None,
            preview_digest=cast(str, preview["preview_digest"]),
            accept=False,
        )
    assert not isinstance(refused.value, CapacityNoCapUnsupported)
    assert env.workspace_queue_count() is None

    applied = apply_selection_preview(
        env.store,
        env.commitment,
        detail=ObservationMode.DETAILED,
        capacity=request,
        scope="workspace",
        session_commitment=None,
        expires_at=None,
        preview_digest=cast(str, preview["preview_digest"]),
        accept=True,
    )
    assert applied["applied"] is True
    budget = cast(dict[str, object], applied["effective_budget"])
    assert budget["selected_queue_count"] == 3000
    assert env.workspace_queue_count() == 3000
    setting = env.store.selection_settings_for(env.commitment).workspace
    assert setting is not None
    assert setting.selection.capacity == ObservationCapacity(3000)
    assert setting.selection.detail is ObservationMode.DETAILED


def test_effective_budget_line_is_unknown_without_a_record() -> None:
    line = observe_cli._effective_budget_line(None)  # pyright: ignore[reportPrivateUsage]
    assert "selected=unknown(unknown)" in line
    assert "no_cap=unknown; " in line


# --- #843: lowering above the fallback byte ceiling keeps a finite drain ---


def _accept_backlog(env: Env, count: int) -> None:
    """Persist rows as if admitted under the larger selection, in one save."""

    store = LocalObservationStore(_state=env.root)
    with store._lock:  # pyright: ignore[reportPrivateUsage]
        state = store._load(env.commitment)  # pyright: ignore[reportPrivateUsage]
        assert state.pending_outbox is not None
        state.pending_outbox.extend(
            ObservationOutboxRow(
                codex_session_id=HOST,
                envelope=ObservationEnvelope(
                    session_commitment=env.session,
                    event_kind="PostToolUse",
                    source_identity=f"backlog:{index}",
                    source=ObservationSource.CODEX_HOOK,
                    cursor=ObservationCursor(
                        source_generation=1,
                        byte_position=0,
                        event_position=index + 1,
                        last_source_commitment="hmac-sha256:" + "a" * 64,
                        mapping_version="codex-obs-hook/1.0.0",
                    ),
                    receipt_time=Timestamp("2026-09-10T00:01:00.000Z"),
                    structural_payload=JsonObject({"tool_name": "shell", "exit_status": 1}),
                    content_object_refs=(),
                    gap_codes=(),
                ),
            )
            for index in range(count)
        )
        store._save(env.commitment, state)  # pyright: ignore[reportPrivateUsage]
    size = store._workspace_path(env.commitment).stat().st_size  # pyright: ignore[reportPrivateUsage]
    assert size > 1_048_576


def _refused_sibling(env: Env, index: int) -> str | None:
    store = LocalObservationStore(_state=env.root)
    (row,) = store.list_pending_outbox_rows(env.commitment)[:1]
    sibling = "hmac-sha256:" + f"{index + 2:x}" * 64
    envelope = replace(
        row.envelope,
        session_commitment=sibling,
        source_identity=f"sibling:{index}",
    )
    return store.enqueue_outbox(env.commitment, f"codex-sibling-{index}", envelope)


def test_revoke_above_the_fallback_ceiling_keeps_accounting_writable(env: Env) -> None:
    env.preview_and_apply("--capacity", "largest", "--persist")
    _accept_backlog(env, 3_000)

    revoked = env.json("selection-revoke", "--persist")
    assert revoked["fallback"]["capacity"] == 512
    assert [_refused_sibling(env, index) for index in range(3)] == ["outbox_overflow"] * 3

    # Accepted rows are preserved; the loss is visible, not silently dropped.
    selection = env.json("selection-status")
    assert selection["effective_capacity"] == 512
    assert selection["queue_count"] == 3_000
    assert selection["admission_allowed"] is False
    assert selection["pressure_state"] == "hard_limit"
    status = env.json("status")
    assert status["undelivered_count"] == 3_000
    assert "outbox_overflow" in status["status"]["gaps"]


def test_session_end_after_a_session_revoke_above_the_ceiling_persists(env: Env) -> None:
    env.preview_and_apply("--capacity", "largest", "--session-id", HOST)
    _accept_backlog(env, 3_000)
    revoked = env.json("selection-revoke", "--session-id", HOST)
    assert revoked["fallback"]["capacity"] == 512
    assert _refused_sibling(env, 0) == "outbox_overflow"

    LocalObservationStore(_state=env.root).note_session_end(env.commitment, env.session)

    store = LocalObservationStore(_state=env.root)
    state = store._load(env.commitment)  # pyright: ignore[reportPrivateUsage]
    assert state.ended_sessions is not None and env.session in state.ended_sessions
    assert store.selection_settings_for(env.commitment).session(env.session) is None
    assert len(store.list_pending_outbox_rows(env.commitment)) == 3_000
    assert env.json("selection-status", "--session-id", HOST)["selected_capacity"] == 512
