"""Service-side redaction of the check-time change (ADR-031, issue #883)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from finishup.adapters.privacy.local_enforcer import scan_exact_bytes
from finishup.application import check_change as check_change_module
from finishup.observability.privacy import EGRESS_CREDENTIAL_PLACEHOLDER
from finishup.ports.change_capture import (
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
    # Heuristic-only values read as the self-describing placeholder, never a bare [REDACTED].
    assert redacted.text.count(EGRESS_CREDENTIAL_PLACEHOLDER) == 600
    assert b"[REDACTED]" not in redacted.text
    assert b"src/parser.ts" in redacted.text


def test_a_value_that_only_looks_like_a_credential_reads_as_withheld_not_as_code() -> None:
    """tb4n5 live-database-cutover: ``password=config.POSTGRES_PASSWORD`` reached the reviewer
    as ``password=[REDACTED]``, which it read as an undefined name (a NameError finding)."""

    line = (
        b"+    return URL.create('postgresql+psycopg',username=config.POSTGRES_USER,"
        b"password=config.POSTGRES_PASSWORD,host=config.POSTGRES_HOST)\n"
    )
    token = b"ghp_" + b"Q" * 36
    text = b"diff --git a/api/db.py b/api/db.py\n" + line + b"+TOKEN = '" + token + b"'\n"

    redacted = _redacted(_capture(text))

    assert redacted.redacted
    assert b"password=" + EGRESS_CREDENTIAL_PLACEHOLDER + b"," in redacted.text
    assert b"config.POSTGRES_PASSWORD" not in redacted.text
    # A concrete credential shape still reads [REDACTED]; both converge to a clean scan.
    assert token not in redacted.text and b"TOKEN = '[REDACTED]'" in redacted.text
    assert scan_exact_bytes(redacted.text) == ()
    assert _redacted(redacted) is redacted


def test_clean_change_is_returned_unchanged() -> None:
    capture = _capture(b"diff --git a/a.py b/a.py\n+print('kept')\n")

    assert _redacted(capture) is capture


def test_change_that_cannot_be_fully_redacted_is_withheld(monkeypatch: pytest.MonkeyPatch) -> None:
    def never_clean(data: bytes, **_: object) -> tuple[bytes, bool]:
        return data + b".", True

    monkeypatch.setattr(check_change_module, "redact_sensitive_content", never_clean)

    with pytest.raises(ChangeCaptureUnavailable) as caught:
        _redacted(_capture(b"+token = forever-matching\n"))
    assert caught.value.reason == "redaction_incomplete"


@pytest.mark.anyio
async def test_unavailable_reason_is_frozen_in_the_binding_and_recovered() -> None:
    from finishup.application.check_change import CheckChangeOutcome, recover_check_time_change

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
    from finishup.application.check_change import capture_structural_check_change

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
    from finishup.application.check_change import task_input_paths
    from finishup.domain.events import (
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
        # Issue #1082: an absolute directory the statement names comes last; only an admitted
        # outside-workspace root ever lists one, and the repository read never opens it.
        "/app/out/",
    )
    assert task_input_paths(case.projection, None) == ("rules/RULEBOOK.txt",)


def _verification_case(*commands: tuple[str, str]) -> object:
    """A case whose recorded command runs are ``(command, outcome)`` pairs, oldest first."""

    from builders.policy_cases import act, make_case, record, res
    from finishup.domain.events import (
        ActionKind,
        ActionRecordedPayload,
        ResultOutcome,
        ResultRecordedPayload,
    )

    actions: dict[Any, Any] = {}
    results: dict[Any, Any] = {}
    for index, (command, outcome) in enumerate(commands, start=1):
        actions[act(index)] = record(
            ActionRecordedPayload(act(index), ActionKind.COMMAND, "verify", command=command),
            2 * index,
        )
        results[res(index)] = record(
            ResultRecordedPayload(res(index), act(index), ResultOutcome(outcome)),
            2 * index + 1,
        )
    return make_case(actions=actions, results=results)


def test_verification_commands_name_their_test_files_newest_first() -> None:
    """Issue #1082: the test a verification ran is the oracle the reviewer needs."""

    from finishup.application.check_change import review_input_paths, verification_input_paths

    case = _verification_case(
        ("pytest -q tests/test_old.py", "failure"),
        ("cat notes/answer.txt", "success"),
        ("python -m pytest tests/test_parser.py::TestBurst::test_order -x", "success"),
        ("node --test ./test/stream.test.mjs", "success"),
        ("pytest 'tests/broken.py", "success"),
    )
    projection = cast(Any, case).projection

    assert verification_input_paths(projection) == (
        "test/stream.test.mjs",
        "tests/test_parser.py",
        "tests/test_old.py",
    )
    statement = "Fix the parser in a.py, b.py, c.py, d.py and e.py."
    ordered, oracle = review_input_paths(projection, statement)
    # Three task files, then the newest oracle, then the rest.
    assert ordered[:5] == ("a.py", "b.py", "c.py", "test/stream.test.mjs", "d.py")
    assert oracle == frozenset(
        {"test/stream.test.mjs", "tests/test_parser.py", "tests/test_old.py"}
    )


def test_an_input_only_a_verification_named_is_labelled_as_its_oracle() -> None:
    from finishup.ports.change_capture import TaskInputFile

    _capture_redacted = getattr(check_change_module, "_capture_redacted")

    class InputPort:
        def capture(
            self,
            workspace: str,
            base: object,
            *,
            priority_paths: tuple[str, ...] = (),
            input_paths: tuple[str, ...] = (),
        ) -> CheckChangeCapture:
            return CheckChangeCapture(
                base="task_start",
                text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
                tracked_files=1,
                untracked_files=0,
                omitted_files=0,
                truncated=False,
                inputs=(
                    TaskInputFile("DESIGN.md", b"# Design\n", 9),
                    TaskInputFile("tests/test_parser.py", b"def test_x(): pass\n", 19),
                ),
            )

    capture = _capture_redacted(
        InputPort(),
        "/repo",
        None,
        (),
        ("DESIGN.md", "/repo/tests/test_parser.py"),
        frozenset({"/repo/tests/test_parser.py"}),
    )

    design, oracle = capture.inputs
    assert design.origin == "task"
    assert oracle.origin == "verification"


def test_outside_inputs_join_the_capture_in_the_room_left_and_are_redacted() -> None:
    """Issue #1082: inputs beneath an admitted root take the same redaction as repository ones,
    fill only the four-input room the repository read left, and need a reader at all."""

    from finishup.ports.change_capture import TaskInputFile

    _capture_redacted = getattr(check_change_module, "_capture_redacted")
    asked: list[tuple[tuple[str, ...], int]] = []

    class InputPort:
        def capture(
            self,
            workspace: str,
            base: object,
            *,
            priority_paths: tuple[str, ...] = (),
            input_paths: tuple[str, ...] = (),
        ) -> CheckChangeCapture:
            return CheckChangeCapture(
                base="task_start",
                text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
                tracked_files=1,
                untracked_files=0,
                omitted_files=0,
                truncated=False,
                inputs=tuple(
                    TaskInputFile(name, b"# Design\n", 9) for name in ("a.md", "b.md", "c.md")
                ),
            )

    secret = b'password = "a8F3kL9qZx7Pw2Rt"\n'

    def reader(values: tuple[str, ...], room: int) -> tuple[TaskInputFile, ...]:
        asked.append((values, room))
        return (
            TaskInputFile("/shared/spec.md", b"spec\n" + secret, 30, origin="outside_workspace"),
            TaskInputFile("/shared/more.md", b"more\n", 5, origin="outside_workspace"),
            # A reader that returns anything else is not trusted with it.
            TaskInputFile("inside.md", b"inside\n", 7),
        )

    paths = ("a.md", "/shared/spec.md", "/repo/inside/notes.md", "/shared/legacy/")
    capture = _capture_redacted(InputPort(), "/repo", None, (), paths, frozenset(), reader)

    assert asked == [(("/shared/spec.md", "/shared/legacy/"), 1)]
    assert [item.path for item in capture.inputs][-1] == "/shared/spec.md"
    assert len(capture.inputs) == 4
    outside = capture.inputs[-1]
    assert outside.origin == "outside_workspace" and outside.redacted
    assert b"a8F3kL9qZx7Pw2Rt" not in outside.text
    assert capture.redacted
    # Without a reader, nothing outside the repository is read.
    plain = _capture_redacted(InputPort(), "/repo", None, (), paths, frozenset(), None)
    assert all(item.origin == "task" for item in plain.inputs)


def test_task_input_files_are_redacted_one_by_one_and_dropped_when_they_cannot_be() -> None:
    from finishup.ports.change_capture import TaskInputFile

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
    assert spec.redacted and b"a8F3kL9qZx7Pw2Rt" not in spec.text
    assert b'password = "' + EGRESS_CREDENTIAL_PLACEHOLDER + b'"' in spec.text
    assert rules == capture.inputs[1]
    # The change itself was clean and stays as it was, but review content was still altered, so
    # the capture discloses it (``check_time_change_redacted``; review of #1045).
    assert redacted.text == capture.text and redacted.redacted
    assert not redacted.truncated


def test_a_task_input_withheld_whole_is_disclosed_as_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review of #1045: an input that cannot be fully redacted is dropped, and that is said."""

    from finishup.ports.change_capture import TaskInputFile

    original = check_change_module.redact_sensitive_content

    def never_clean_for_the_input(data: bytes, **options: bytes | None) -> tuple[bytes, bool]:
        if b"WITHHELD_INPUT_MARKER" in data:
            return data + b".", True
        return original(data, **options)

    monkeypatch.setattr(check_change_module, "redact_sensitive_content", never_clean_for_the_input)
    capture = CheckChangeCapture(
        base="task_start",
        text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        inputs=(TaskInputFile("spec.md", b"WITHHELD_INPUT_MARKER\n", 22),),
    )

    redacted = _redacted(capture)

    assert redacted.inputs == ()
    assert redacted.text == capture.text and redacted.redacted


def test_clean_task_inputs_leave_the_capture_unmarked() -> None:
    from finishup.ports.change_capture import TaskInputFile

    capture = CheckChangeCapture(
        base="task_start",
        text=b"diff --git a/a.py b/a.py\n+print('kept')\n",
        tracked_files=1,
        untracked_files=0,
        omitted_files=0,
        truncated=False,
        inputs=(TaskInputFile("rules.md", b"# Rules\nno secrets here\n", 24),),
    )

    assert _redacted(capture) == capture


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

    from finishup.ports.change_capture import (
        NestedUntrackedBaseline,
        TaskChangeBase,
        UntrackedBaselineFile,
    )

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
                nested_untracked=(
                    NestedUntrackedBaseline(
                        "api", True, (UntrackedBaselineFile("notes.md", "sha256:" + "1" * 64),)
                    ),
                ),
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
