"""Service-side redaction of the check-time change (ADR-031, issue #883)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from yoetz.adapters.privacy.local_enforcer import scan_exact_bytes
from yoetz.application import check_change as check_change_module
from yoetz.ports.change_capture import (
    ChangeCaptureUnavailable,
    CheckChangeCapture,
    CheckWorkspaceSource,
)

_redacted = getattr(check_change_module, "_redacted")


def _capture(text: bytes) -> CheckChangeCapture:
    return CheckChangeCapture(
        base="task_start",
        text=text,
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
    )


def test_parser_source_with_more_matches_than_one_scan_reports_is_fully_redacted() -> None:
    """A change can repeat credential-shaped ``token = ...`` lines far past one scan's cap.

    The meriyah parser shape (``token = parser.getToken()``) is source code and no longer
    matches (issue #982), so the repeated line is a quoted credential-shaped literal.
    """

    lines = b"".join(
        f'+  const token = "a8F3kL9q{index:04d}Zx";\n'.encode() for index in range(600)
    )
    text = b"diff --git a/src/parser.ts b/src/parser.ts\n" + lines

    redacted = _redacted(_capture(text))

    assert redacted.redacted
    assert scan_exact_bytes(redacted.text) == ()
    assert redacted.text.count(b"[REDACTED]") == 600
    assert b"src/parser.ts" in redacted.text


def test_clean_change_is_returned_unchanged() -> None:
    capture = _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    assert _redacted(capture) is capture


def test_change_that_cannot_be_fully_redacted_is_withheld(monkeypatch: pytest.MonkeyPatch) -> None:
    def never_clean(data: bytes) -> tuple[bytes, bool]:
        return data + b".", True

    monkeypatch.setattr(check_change_module, "redact_sensitive_content", never_clean)

    with pytest.raises(ChangeCaptureUnavailable) as caught:
        _redacted(_capture(b"+token = forever-matching\n"))
    assert caught.value.reason == "redaction_incomplete"


@pytest.mark.anyio
async def test_unavailable_reason_is_frozen_in_the_binding_and_recovered() -> None:
    from yoetz.application.check_change import CheckChangeOutcome, recover_check_time_change

    outcome = CheckChangeOutcome(unavailable=True, reason="changed_during_capture")
    binding = outcome.binding_json()
    assert isinstance(binding, dict) and binding["reason"] == "changed_during_capture"

    recovered = await recover_check_time_change(cast(Any, None), dict(binding))

    assert recovered == outcome
    legacy = {key: value for key, value in binding.items() if key != "reason"}
    assert await recover_check_time_change(cast(Any, None), legacy) == CheckChangeOutcome(
        unavailable=True
    )
    with pytest.raises(ValueError):
        await recover_check_time_change(cast(Any, None), {**binding, "reason": "free text"})
    with pytest.raises(ValueError):
        CheckChangeOutcome(unavailable=False, reason="git_failed")


@pytest.mark.anyio
async def test_structural_capture_does_not_fallback_to_legacy_content_port() -> None:
    from yoetz.application.check_change import capture_structural_check_change

    class LegacyPort:
        def capture(self, workspace: str, base: object) -> CheckChangeCapture:
            raise AssertionError("legacy content capture must not be called")

    source = CheckWorkspaceSource("/workspace", "hmac-sha256:" + "a" * 64)
    result = await capture_structural_check_change(
        runtime=cast(Any, SimpleNamespace(ledger=SimpleNamespace())),
        source=source,
        route_repository_commitment=source.repository_commitment,
        port=cast(Any, LegacyPort()),
        clock=cast(Any, None),
        request_id="req_30000000-0000-4000-8000-000000000001",
    )

    assert result == (None, "metadata_unavailable")


def test_declared_deliverables_reach_the_port_and_a_plain_port_keeps_working() -> None:
    """tb4n2 R7: the ordering hint is passed only when there is one, so older ports still work."""

    _capture_redacted = getattr(check_change_module, "_capture_redacted")
    seen: list[tuple[str, ...]] = []

    class OrderingPort:
        def capture(
            self, workspace: str, base: object, *, priority_paths: tuple[str, ...] = ()
        ) -> CheckChangeCapture:
            seen.append(priority_paths)
            return _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    class PlainPort:
        def capture(self, workspace: str, base: object) -> CheckChangeCapture:
            return _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    _capture_redacted(OrderingPort(), "/repo", None, ("out.json",))
    _capture_redacted(PlainPort(), "/repo", None)

    assert seen == [("out.json",)]


# --- Issue #1045: task input files and the task-start snapshot -----------------------------------


def test_task_input_paths_are_the_files_the_statement_names_then_declared_inputs() -> None:
    from builders.policy_cases import make_case, obl, obligation_record, plan_record
    from yoetz.application.check_change import task_input_paths
    from yoetz.domain.events import (
        ObligationPublishedPayload,
        ObligationStatus,
        PlanPublishedPayload,
        RequestedItem,
        RequestedItemKind,
        RequestedItemRole,
    )

    obligation = obligation_record(
        ObligationPublishedPayload(
            obl(1),
            "Port the form",
            "form.py behaves like the VBA form",
            ObligationStatus.OPEN,
            requested_items=(
                RequestedItem(
                    RequestedItemKind.FILE, "rules/RULEBOOK.txt", RequestedItemRole.INPUT
                ),
                RequestedItem(RequestedItemKind.FILE, "form.py", RequestedItemRole.OUTPUT),
            ),
        ),
        1,
    )
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Port the form", (obl(1),)), 1)},
        obligations={obl(1): obligation},
        extra_refs=(obl(1),),
    )
    statement = (
        "Port the VBA UserForm in /app/vba/UserForm1.frm to Python (see `DESIGN.md` and "
        "spec/rules.txt). Use main.c, e.g. numpy 3.10, i.e. https://example.invalid/x.md. "
        "Write the result to /app/out/ and DESIGN.md again."
    )

    paths = task_input_paths(case.projection, statement)

    assert paths == (
        "/app/vba/UserForm1.frm",
        "DESIGN.md",
        "spec/rules.txt",
        "main.c",
        "rules/RULEBOOK.txt",
    )
    assert task_input_paths(case.projection, None) == ("rules/RULEBOOK.txt",)


def test_task_input_files_are_redacted_one_by_one_and_dropped_when_they_cannot_be() -> None:
    from yoetz.ports.change_capture import TaskInputFile

    secret = b'password = "a8F3kL9qZx7Pw2Rt"\n'
    capture = CheckChangeCapture(
        base="task_start",
        text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        inputs=(
            TaskInputFile("spec.md", b"# Spec\n" + secret, 7 + len(secret)),
            TaskInputFile("rules.md", b"# Rules\nno secrets here\n", 24),
        ),
    )

    redacted = _redacted(capture)

    spec, rules = redacted.inputs
    assert spec.redacted and b"a8F3kL9qZx7Pw2Rt" not in spec.text and b"[REDACTED]" in spec.text
    assert rules == capture.inputs[1]
    # The change itself was clean, so it is not marked redacted.
    assert redacted.text == capture.text and not redacted.redacted


def test_task_inputs_reach_the_port_only_when_asked_for() -> None:
    _capture_redacted = getattr(check_change_module, "_capture_redacted")
    seen: list[tuple[str, ...]] = []

    class InputPort:
        def capture(
            self,
            workspace: str,
            base: object,
            *,
            priority_paths: tuple[str, ...] = (),
            input_paths: tuple[str, ...] = (),
        ) -> CheckChangeCapture:
            seen.append(input_paths)
            return _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    class PlainPort:
        def capture(self, workspace: str, base: object) -> CheckChangeCapture:
            return _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    _capture_redacted(InputPort(), "/repo", None, (), ("DESIGN.md",))
    _capture_redacted(PlainPort(), "/repo", None, (), ())

    assert seen == [("DESIGN.md",)]


@pytest.mark.anyio
async def test_first_check_pin_drops_a_task_start_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the task's own start says which untracked files predate it (#1045)."""

    from yoetz.ports.change_capture import TaskChangeBase, UntrackedBaselineFile

    _pin = getattr(check_change_module, "_pin_first_check_base")
    stored: list[bytes] = []

    class Port:
        def read_task_base(self, workspace: str) -> TaskChangeBase:
            return TaskChangeBase(
                "sha1",
                "a" * 40,
                untracked=(UntrackedBaselineFile("x.txt", "sha256:" + "0" * 64),),
                untracked_complete=True,
                nested=(("api", "b" * 40),),
            )

    class Ledger:
        async def record_task_change_base(self, ref: object) -> bool:
            return True

        async def load_task_change_base(self) -> object:
            return None

    async def store(runtime: object, data: bytes, media_type: str, clock: object) -> object:
        stored.append(data)
        return object()

    monkeypatch.setattr(check_change_module, "_store", store)
    runtime = SimpleNamespace(ledger=Ledger())

    pinned = await _pin(runtime, Port(), "/repo", object(), "req_x")

    assert pinned == TaskChangeBase("sha1", "a" * 40, "first_check")
    assert b"untracked" not in stored[0] and b"nested" not in stored[0]
