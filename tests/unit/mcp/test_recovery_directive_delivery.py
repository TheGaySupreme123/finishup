"""Real producers deliver typed recovery directives to native text without any injected token.

Review of the first ADR-030 change found that the registry mapped reasons to directives but
production attached almost none of them: an ``unsorted_set_field`` rejection reached the model as
``Reason: unsorted_set_field at /evidence_refs.`` with the registered directive absent, a lost
first ``start`` received a write directive it could not follow, and the benchmark's malformed
``codex:/root`` actor id arrived as ``Error INVALID_REQUEST; retryable: no`` with neither its
field nor a way forward. Every test here starts at a real producer -- the bridge's argument
validator, its control-error mapper, the shared public-error builder, or the CLI -- and asserts the
serialized wire body and the text a Claude, Codex, or Cursor host actually reads.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
from mcp import types

import finishup.cli.app as cli
import finishup.mcp.server as bridge
from finishup.cli.render import render_human_error
from finishup.mcp.errors import build_public_error_result
from finishup.mcp.summaries import MAX_SUMMARY_BYTES
from finishup.ports.control import ControlError
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import (
    CheckRequest,
    OperationFailureModel,
    PublishWorkResultModel,
    StartRequest,
)
from finishup.protocol.recovery import RECOVERY_DIRECTIVES

_REQUEST = "req_80d0cc7a-150f-4d7b-9aa3-a50312db0078"
_CORRELATION = "err_2f56f4b8-2852-40b4-8052-9c5748fbf053"
_SUMMARY_HOSTS = ("generic", "codex", "claude")


def _text(result: types.CallToolResult) -> str:
    content = cast(list[Any], result.content)
    return cast(str, content[0].text)


def _error_of(result: types.CallToolResult) -> dict[str, object]:
    structured = cast(dict[str, object], result.structuredContent)
    return cast(dict[str, object], structured["error"])


def _benchmark_start_body(actor_id: str) -> dict[str, object]:
    """The exact ``start`` the archived Codex attempt sent, differing only in the actor id."""

    return {
        "actor": {
            "actor_id": actor_id,
            "actor_type": "model_backed_worker",
            "display_name": "Codex",
        },
        "client": {"kind": "codex_cli", "version": "5.6", "integration": "cooperative_mcp"},
        "mode": "create_or_attach",
        "protocol_version": "0.1",
        "request_id": _REQUEST,
        "requested_view": "compact",
        "schema_version": "1.0.0",
        "task_title": "Fix Go-side calls and isolation for compiled script functions",
        "workspace_ref": "/app",
        "external_ref": "compiled-function-go-invocation-isolation",
    }


class TestMalformedActorIdRegression:
    """The archived ``codex:/root`` rejection now names its field and its correction path."""

    @pytest.mark.anyio
    @pytest.mark.parametrize("host_profile", _SUMMARY_HOSTS)
    async def test_native_text_names_the_rejected_field_and_the_correction_path(
        self, host_profile: str
    ) -> None:
        runtime = bridge.build_bridge_runtime(host_profile=cast(Any, host_profile))
        try:
            result = await bridge.dispatch_start(_benchmark_start_body("codex:/root"), runtime)
        finally:
            await bridge.close_bridge_runtime(runtime)

        assert result.isError is True
        error = _error_of(result)
        assert error["code"] == PublicErrorCode.INVALID_REQUEST.value
        assert error["retryable"] is False
        assert error["safe_details"] == {
            "continuation": "input_correction_new_identity",
            "fields": ["/actor/actor_id"],
            "reasons": ["invalid_type_or_value"],
        }
        text = _text(result)
        assert text.startswith("Error INVALID_REQUEST; retryable: no;")
        assert "Rejected: invalid_type_or_value at /actor/actor_id." in text
        assert "Continuation: input_correction_new_identity." in text
        assert "NEW request_id" in text
        assert "codex:/root" not in text
        assert len(text.encode("ascii")) <= MAX_SUMMARY_BYTES

    def test_the_corrected_body_the_attempt_then_sent_validates(self) -> None:
        StartRequest.model_validate(_benchmark_start_body("codex:root"))
        with pytest.raises(Exception):
            StartRequest.model_validate(_benchmark_start_body("codex:/root"))

    def test_the_correction_directive_is_distinct_from_ambiguous_write_recovery(self) -> None:
        correction = RECOVERY_DIRECTIVES["input_correction_new_identity"]
        assert "before any write" in correction.directive
        assert "NEW request_id" in correction.directive
        assert "view=operation" not in correction.directive


class TestTimeoutDirectivesFromTheBridgeMapper:
    """The control-error mapper is the one producer that knows what timed out."""

    @pytest.mark.parametrize(
        ("operation", "token"),
        (
            ("start", "start_timeout_same_identity"),
            ("publish_work", "write_timeout_same_identity"),
            ("check", "write_timeout_same_identity"),
            ("respond", "write_timeout_same_identity"),
            ("receipt", "write_timeout_same_identity"),
            ("status", "read_timeout_new_identity"),
        ),
    )
    def test_each_operation_kind_carries_its_own_token_and_text(
        self, operation: str, token: str
    ) -> None:
        result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
            ControlError("request_timeout", retryable=True, correlation_id=_CORRELATION),
            request_id=_REQUEST,
            operation=operation,
        )
        error = _error_of(result)
        details = cast(dict[str, object], error["safe_details"])
        expected = {"continuation": token, "reason_code": "request_timeout"}
        if operation in {"publish_work", "check", "respond", "receipt"}:
            expected["replay_request_id"] = _REQUEST
        assert details == expected
        text = _text(result)
        assert f"Continuation: {token}." in text
        assert RECOVERY_DIRECTIVES[token].directive in text

    def test_a_lost_first_start_is_told_to_replay_not_to_query_status(self) -> None:
        """Issue #669 review: a first start may hold neither session nor writer id."""

        result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
            ControlError("request_timeout", retryable=True, correlation_id=_CORRELATION),
            request_id=_REQUEST,
            operation="start",
        )
        text = _text(result)
        assert "replay the exact same start body once with this same request_id" in text
        assert "view=operation" not in text
        assert "same request_id" in str(_error_of(result)["message"])


_SESSION = "ses_00000000-0000-4000-8000-000000000001"
_WRITER = "wri_00000000-0000-4000-8000-000000000001"


def _check_body(mode: str) -> dict[str, object]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _REQUEST,
        "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "session_id": _SESSION,
        "writer_id": _WRITER,
        "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
        "mode": mode,
    }


class _TimingOutCheckClient:
    """A service client whose ``check`` records its deadline, then fails as the daemon would."""

    def __init__(self, failure: BaseException) -> None:
        self.failure = failure
        self.deadlines: list[int | None] = []

    async def check(self, request: object, *, deadline_ms: int | None = None, **_: object) -> Any:
        del request
        self.deadlines.append(deadline_ms)
        raise self.failure

    async def close(self) -> None:
        return None


class TestAnInspectionFailsAsARead:
    """Review of #1048: ``check`` ``mode: inspect`` records nothing (ADR-047).

    The daemon already classified it read-only, but the bridge and the CLI classified by operation
    name, so a timed-out inspection was told it "MAY already have committed", carried a
    ``replay_request_id`` for an operation that never exists, and waited on the 300-second budget
    of a check that may run an AI-powered review. A minting check keeps all of that.
    """

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("mode", "deadline", "token"),
        (
            ("inspect", 30_000, "read_timeout_new_identity"),
            ("deterministic_only", 300_000, "write_timeout_same_identity"),
            ("semantic_required", 300_000, "write_timeout_same_identity"),
        ),
    )
    async def test_a_timed_out_inspection_is_a_read_with_the_status_deadline(
        self, monkeypatch: pytest.MonkeyPatch, mode: str, deadline: int, token: str
    ) -> None:
        for name in ("", "_CHECK", "_STATUS"):
            monkeypatch.delenv(f"FINISHUP_MCP_DEADLINE_MS{name}", raising=False)
        client = _TimingOutCheckClient(
            ControlError(
                "request_timeout", retryable=True, correlation_id=_CORRELATION, phase="handler"
            )
        )

        async def ensure(*_args: object, **_kwargs: object) -> _TimingOutCheckClient:
            return client

        monkeypatch.setattr(bridge, "ensure_service_client", ensure)
        runtime = bridge.build_bridge_runtime()
        try:
            result = await bridge.dispatch_check(_check_body(mode), runtime)
        finally:
            await bridge.close_bridge_runtime(runtime)

        assert client.deadlines == [deadline]
        error = _error_of(result)
        assert error["code"] == PublicErrorCode.SERVICE_UNAVAILABLE.value
        assert error["retryable"] is True
        details = cast(dict[str, object], error["safe_details"])
        expected: dict[str, object] = {
            "continuation": token,
            "phase": "handler",
            "reason_code": "request_timeout",
        }
        if mode != "inspect":
            expected["replay_request_id"] = _REQUEST
        assert details == expected
        text = _text(result)
        assert f"Continuation: {token}." in text
        assert ("may still have committed" in str(error["message"])) is (mode != "inspect")

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("mode", "token"),
        (
            ("inspect", "read_timeout_new_identity"),
            ("deterministic_only", "write_timeout_same_identity"),
        ),
    )
    async def test_an_inspection_the_bridge_failed_to_send_is_repeated_as_a_read(
        self, monkeypatch: pytest.MonkeyPatch, mode: str, token: str
    ) -> None:
        client = _TimingOutCheckClient(RuntimeError("bridge fault"))

        async def ensure(*_args: object, **_kwargs: object) -> _TimingOutCheckClient:
            return client

        monkeypatch.setattr(bridge, "ensure_service_client", ensure)
        runtime = bridge.build_bridge_runtime()
        try:
            result = await bridge.dispatch_check(_check_body(mode), runtime)
        finally:
            await bridge.close_bridge_runtime(runtime)

        error = _error_of(result)
        details = cast(dict[str, object], error["safe_details"])
        assert details == {"continuation": token, "reason_code": "bridge_invoke_failed"}
        # The remedy never names an inspection among the writes to replay (PR #1054 review).
        assert "check other than an inspection" in str(error["message"])

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("mode", "token"),
        (
            ("inspect", "read_timeout_new_identity"),
            ("deterministic_only", "write_timeout_same_identity"),
        ),
    )
    async def test_the_cli_names_a_timed_out_inspection_a_read(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        mode: str,
        token: str,
    ) -> None:
        client = _TimingOutCheckClient(ControlError("request_timeout", retryable=True))

        async def build(*_args: object, **_kwargs: object) -> _TimingOutCheckClient:
            return client

        monkeypatch.setattr(cli, "build_service_client", build)
        code = await cli._call_workflow(  # pyright: ignore[reportPrivateUsage]
            "check", CheckRequest, None, json.dumps(_check_body(mode)), False, 5_000
        )
        assert code != 0
        # The CLI keeps the caller's explicit ``--deadline-ms`` for every mode.
        assert client.deadlines == [5_000]
        captured = capsys.readouterr().err
        assert f"Continuation: {token}" in captured.splitlines()
        assert RECOVERY_DIRECTIVES[token].directive in captured


class TestReasonCodedProducersReachNativeText:
    """A reason code alone is enough: the token is attached where the error is built."""

    @pytest.mark.parametrize("host_profile", _SUMMARY_HOSTS)
    def test_set_order_rejection_from_the_public_error_builder(self, host_profile: str) -> None:
        wire = build_public_error_result(
            PublicErrorCode.INVALID_REQUEST,
            "The event batch is invalid.",
            False,
            _CORRELATION,
            request_id=_REQUEST,
            safe_details={"reason_code": "unsorted_set_field", "field": "/evidence_refs"},
        )
        error = cast(dict[str, object], wire["error"])
        assert error["safe_details"] == {
            "continuation": "sorted_set_required",
            "field": "/evidence_refs",
            "reason_code": "unsorted_set_field",
        }
        result = bridge.result_from_public_model(
            PublishWorkResultModel.model_validate(wire), host_profile=cast(Any, host_profile)
        )
        text = _text(result)
        assert "Reason: unsorted_set_field at /evidence_refs." in text
        assert "Continuation: sorted_set_required." in text
        assert RECOVERY_DIRECTIVES["sorted_set_required"].directive in text

    def test_cursor_receives_the_token_in_its_canonical_json_copy(self) -> None:
        error = PublicOperationError(
            PublicErrorCode.FRONTIER_CONFLICT,
            "The event batch is invalid.",
            True,
            correlation_id=_CORRELATION,
            safe_details={"reason_code": "frontier_changed"},
        )
        model = PublishWorkResultModel.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "ok": False,
                "error": error.as_public_dict(),
                "request_id": _REQUEST,
            }
        )
        result = bridge.result_from_public_model(model, host_profile="cursor")
        body = json.loads(_text(result))
        assert body["error"]["safe_details"]["continuation"] == "frontier_refresh_required"

    def test_service_side_session_superseded_rebinds(self) -> None:
        error = PublicOperationError(
            PublicErrorCode.SESSION_CONFLICT,
            "The session was superseded.",
            False,
            correlation_id=_CORRELATION,
            safe_details={"reason_code": "session_superseded"},
        )
        assert error.as_public_dict()["safe_details"] == {
            "continuation": "session_rebind_required",
            "reason_code": "session_superseded",
        }


class TestCliSurfaces:
    def test_a_real_error_renders_its_directive_lines(self) -> None:
        error = PublicOperationError(
            PublicErrorCode.EVENT_INVALID,
            "The event batch is invalid.",
            False,
            correlation_id=_CORRELATION,
            safe_details={"reason_code": "duplicate_set_member", "field": "/event_drafts/0"},
        )
        failure = OperationFailureModel.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "ok": False,
                "error": error.as_public_dict(),
            }
        )
        rendered = render_human_error(failure.error)
        lines = rendered.splitlines()
        assert lines[0] == "EVENT_INVALID: The event batch is invalid."
        assert "Continuation: sorted_set_required" in lines
        assert any(
            line.startswith("Guidance: finishup://guidance/publication-policy.md") for line in lines
        )

    def test_lifecycle_refusal_line_carries_the_local_directive(self) -> None:
        """``continuation_for_local_reason`` previously had no production caller."""

        line = cli._bounded_failure_line("service_already_running")  # pyright: ignore[reportPrivateUsage]
        assert line.splitlines()[0].startswith("service_already_running")
        assert "Continuation: service_holder_busy" in line
        assert RECOVERY_DIRECTIVES["service_holder_busy"].directive in line

    def test_workflow_timeout_names_the_operation_kind(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = cli._control_failure(  # pyright: ignore[reportPrivateUsage]
            ControlError("request_timeout", retryable=True, correlation_id=_CORRELATION),
            operation="start",
        )
        captured = capsys.readouterr().err
        lines = captured.splitlines()
        assert code != 0
        assert lines[0].startswith("service_unavailable: request_timeout:")
        # The correlation annotation stays on the token line, ahead of the directive lines.
        assert lines[0].endswith(f"; correlation_id {_CORRELATION}")
        assert "Continuation: start_timeout_same_identity" in lines
        assert lines[-1] == RECOVERY_DIRECTIVES["start_timeout_same_identity"].nudge
        assert "finishup service run" not in captured

    def test_a_timeout_of_unknown_operation_keeps_the_generic_line(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cli._control_failure(ControlError("request_timeout", retryable=True))  # pyright: ignore[reportPrivateUsage]
        assert "Continuation:" not in capsys.readouterr().err
