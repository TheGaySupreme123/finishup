"""The post-compaction recap on every host's compaction start (ADR-044, issue #1027).

Real ``status`` results (``builders.status_wire``) go through the real hook entry points: the
Codex re-ground hook (``hooks session-start``, source ``compact``), and the shared observe pass
Claude Code and Cursor use. The service is a recording fake that answers by requested view.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from builders.status_wire import CompactStatus, compact_status, obligations_status
from yoetz.adapters.integrations.codex_lifecycle import mapping_from_start_ids, store_mapping
from yoetz.adapters.integrations.observation_local import LocalObservationStore
from yoetz.cli.hooks import handle_session_start
from yoetz.cli.observe_hooks import (
    handle_claude_observe,
    handle_cursor_observe,
    handle_observe,
    map_hook_payload_to_envelope,
)
from yoetz.domain.compaction_recap import RECAP_CONTEXT_LIMIT
from yoetz.domain.observation import ObservationSource

_HELD_IDS_CUE = "For compaction in an already-started host session, use your held current ids"


class _Service:
    """A status service answering the compact and obligations views, recording the views asked."""

    def __init__(self, compact: CompactStatus, obligations: object | None = None) -> None:
        self.compact = compact
        self.obligations = obligations
        self.views: list[str] = []
        self.fail_obligations = False

    async def status(self, request: object, *, deadline_ms: int | None = None) -> object:
        assert deadline_ms is not None
        view = str(getattr(request, "view"))
        self.views.append(view)
        if view == "obligations":
            if self.fail_obligations or self.obligations is None:
                raise TimeoutError("obligations view unavailable")
            return self.obligations
        return self.compact.result

    async def close(self) -> None:
        return None

    async def start(self, *_args: Any, **_kwargs: Any) -> object:
        raise AssertionError("a compaction start must not create ledger events")


def _connector(service: _Service) -> Callable[..., Any]:
    async def connect(_kind: object, **_kwargs: object) -> _Service:
        return service

    return connect


def _service() -> _Service:
    compact = compact_status(
        sequence="604",
        open_obligations=["Port the kimi detector with a regression test", None],
        declared=4,
        findings=[
            ("task_requirement_unmet", 1, "Requirement 3 has no recorded verification"),
            ("completion_with_open_obligations", 2, None),
        ],
        receipt_blocking=1,
        latest_check=("action_required", "600"),
    )
    obligations = obligations_status(
        compact,
        [
            ("open", [("file", "out/result.json", "output"), ("file", "data/in.csv", "input")]),
            ("resolved", [("directory", "out/figures", "output"), ("command", "pytest -q", None)]),
        ],
    )
    return _Service(compact, obligations)


def _mapped(tmp_path: Path, session: str, service: _Service) -> None:
    store_mapping(
        mapping_from_start_ids(
            codex_session_id=session,
            yoetz_task_id=service.compact.task_id,
            yoetz_session_id=service.compact.session_id,
            yoetz_writer_id=service.compact.writer_id,
            last_frontier="0:genesis",
        ),
        _state=tmp_path,
    )


def _consented(tmp_path: Path) -> LocalObservationStore:
    store = LocalObservationStore(_state=tmp_path)
    store.grant_consent(store.workspace_commitment(str(tmp_path.resolve())))
    return store


def _codex_context(
    tmp_path: Path, service: _Service, *, source: str, session: str = "codex-recap"
) -> tuple[str, int]:
    _consented(tmp_path)
    _mapped(tmp_path, session, service)
    stdout = io.BytesIO()
    code = handle_session_start(
        stdin_bytes=json.dumps(
            {"session_id": session, "source": source, "cwd": str(tmp_path)}
        ).encode(),
        stdout=stdout,
        _state=tmp_path,
        connect=_connector(service),
        workspace=str(tmp_path),
    )
    assert code == 0
    body = json.loads(stdout.getvalue().decode())
    return body["hookSpecificOutput"]["additionalContext"], len(service.views)


def test_codex_compaction_start_carries_the_sourced_recap_after_the_held_ids_cue(
    tmp_path: Path,
) -> None:
    service = _service()
    context, _ = _codex_context(tmp_path, service, source="compact")

    # The re-ground hook reads compact then obligations; the observe pass it delegates to reads
    # compact once more for its own startup context and asks for no recap (one carrier only).
    assert service.views[:2] == ["compact", "obligations"]
    assert service.views.count("obligations") == 1
    assert _HELD_IDS_CUE in context
    assert context.index(_HELD_IDS_CUE) < context.index("Yoetz recap after context compaction")
    for needle in (
        service.compact.task_id,
        service.compact.session_id,
        service.compact.writer_id,
        "frontier: 604",
        service.compact.obligation_ids[0],
        "Port the kimi detector with a regression test",
        service.compact.finding_ids[0],
        "task_requirement_unmet",
        "last check: action_required on frontier 600",
        service.compact.check_event_id or "",
        "out/result.json",
        "out/figures",
        "readiness: action_required",
    ):
        assert needle in context, needle
    assert "data/in.csv" not in context  # an input is not a deliverable
    assert "pytest -q" not in context  # a command is not a deliverable
    assert "(text withheld by the disclosure policy)" in context  # withheld text stays withheld
    assert len(context) <= RECAP_CONTEXT_LIMIT
    assert context.isascii()


def test_codex_resume_start_keeps_the_plain_reground_without_a_recap(tmp_path: Path) -> None:
    service = _service()
    context, _ = _codex_context(tmp_path, service, source="resume")

    assert "obligations" not in service.views
    assert _HELD_IDS_CUE in context
    assert "Yoetz recap" not in context


def test_the_recap_names_deliverables_unavailable_when_the_second_read_fails(
    tmp_path: Path,
) -> None:
    service = _service()
    service.fail_obligations = True
    context, _ = _codex_context(tmp_path, service, source="compact")

    assert "declared deliverables: unavailable, the obligations view was not read" in context
    assert service.compact.finding_ids[0] in context  # everything else survives


def test_a_status_without_a_frontier_or_page_leaves_the_startup_context_unchanged(
    tmp_path: Path,
) -> None:
    class _Bare:
        task_id = ""
        session_id = ""
        writer_id = ""
        head_frontier = type("F", (), {"sequence": "3", "head_digest": "sha256:" + "c" * 64})()

    class _BareResult:
        root = _Bare()

    service = _service()
    _Bare.task_id = service.compact.task_id
    _Bare.session_id = service.compact.session_id
    _Bare.writer_id = service.compact.writer_id
    bare = _Service(service.compact)

    async def status(_request: object, *, deadline_ms: int | None = None) -> object:
        del deadline_ms
        bare.views.append("compact")
        return _BareResult()

    bare.status = status  # type: ignore[method-assign]
    context, _ = _codex_context(tmp_path, bare, source="compact")

    assert _HELD_IDS_CUE in context
    assert "frontier 3:sha256:" in context
    assert "Yoetz recap after context compaction" in context  # frontier present: recap composes
    assert "plan: unreported declared" in context  # ...and says what the status did not carry
    assert "last check: not reported by this status" in context


def test_undelivered_work_rows_are_disclosed_in_the_recap(tmp_path: Path) -> None:
    service = _service()
    store = _consented(tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.bind_codex_session(workspace, "codex-recap")
    commitment = store.session_commitment("codex-recap")
    for ordinal, kind in enumerate(("PostToolUse", "PostCompact"), start=1):
        envelope = map_hook_payload_to_envelope(
            kind,
            {
                "session_id": "codex-recap",
                "hook_event_name": kind,
                "tool_name": "Bash",
                "tool_use_id": f"call-{ordinal}",
                "exit_status": 0,
            },
            session_commitment=commitment,
            event_ordinal=ordinal,
            key_material=store.key_material(),
            source=ObservationSource.CODEX_HOOK,
        )
        store.enqueue_outbox(workspace, "codex-recap", envelope)
    context, _ = _codex_context(tmp_path, service, source="compact")

    # One tool row counts; the lifecycle row adds no ledger work and is not counted.
    assert "1 local observation row(s) were not yet in the ledger" in context


def _claude_context(tmp_path: Path, service: _Service, *, source: str) -> tuple[str, list[str]]:
    _consented(tmp_path)
    _mapped(tmp_path, "claude:recap-session", service)
    stdout = io.BytesIO()
    code = handle_claude_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {
                "session_id": "recap-session",
                "hook_event_name": "SessionStart",
                "source": source,
                "cwd": str(tmp_path),
            }
        ).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=_connector(service),
    )
    assert code == 0
    output = json.loads(stdout.getvalue().decode())
    # A ``clear`` start is a local fence and emits no context at all.
    return output.get("hookSpecificOutput", {}).get("additionalContext", ""), service.views


def test_claude_code_compaction_start_carries_the_recap(tmp_path: Path) -> None:
    service = _service()
    context, views = _claude_context(tmp_path, service, source="compact")

    assert views[:2] == ["compact", "obligations"]
    assert "Yoetz recap after context compaction" in context
    assert service.compact.finding_ids[0] in context
    assert "out/result.json" in context
    assert len(context) <= RECAP_CONTEXT_LIMIT


@pytest.mark.parametrize("source", ["startup", "resume", "clear"])
def test_claude_code_other_starts_carry_no_recap(tmp_path: Path, source: str) -> None:
    service = _service()
    context, views = _claude_context(tmp_path, service, source=source)

    assert "Yoetz recap" not in context
    assert "obligations" not in views


def test_cursor_compaction_start_carries_the_recap_when_the_host_reports_it(
    tmp_path: Path,
) -> None:
    """Cursor's certified profile documents no post-compaction start; if one reports
    ``source: compact`` the shared pass serves it exactly as Claude Code's.
    """

    service = _service()
    _consented(tmp_path)
    _mapped(tmp_path, "cursor:recap-session", service)
    stdout = io.BytesIO()
    code = handle_cursor_observe(
        event_name="sessionStart",
        stdin_bytes=json.dumps(
            {
                "session_id": "recap-session",
                "conversation_id": "recap-session",
                "hook_event_name": "sessionStart",
                "source": "compact",
                "workspace_roots": [str(tmp_path)],
            }
        ).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=_connector(service),
    )
    assert code == 0
    context = json.loads(stdout.getvalue().decode())["additional_context"]

    assert "Yoetz recap after context compaction" in context
    assert service.compact.finding_ids[0] in context


def test_the_codex_observe_pass_leaves_the_recap_to_the_reground_hook(tmp_path: Path) -> None:
    """Both Codex SessionStart hooks run on a compact start; only one may carry the recap."""

    service = _service()
    _consented(tmp_path)
    _mapped(tmp_path, "codex-recap", service)
    stdout = io.BytesIO()
    handle_observe(
        event_name="SessionStart",
        stdin_bytes=json.dumps(
            {
                "session_id": "codex-recap",
                "hook_event_name": "SessionStart",
                "source": "compact",
                "cwd": str(tmp_path),
            }
        ).encode(),
        stdout=stdout,
        workspace=str(tmp_path),
        _state=tmp_path,
        connect=_connector(service),
        source=ObservationSource.CODEX_HOOK,
    )
    context = json.loads(stdout.getvalue().decode())["hookSpecificOutput"]["additionalContext"]

    assert _HELD_IDS_CUE in context
    assert "Yoetz recap" not in context
    assert "obligations" not in service.views


def test_the_recap_never_reaches_the_default_context_bound_by_accident() -> None:
    """Only a caller that asks for the recap bound gets it; every other context stays at 2,000."""

    from yoetz.cli.hook_io import claude_context_output, context_output, cursor_context_output

    def text(output: object, *path: str) -> str:
        node: Any = output
        for key in path:
            node = node[key]
        return str(node)

    long_text = "x" * 3_000
    assert (
        len(
            text(
                context_output("SessionStart", long_text), "hookSpecificOutput", "additionalContext"
            )
        )
        == 2_000
    )
    assert (
        len(
            text(
                claude_context_output("SessionStart", long_text),
                "hookSpecificOutput",
                "additionalContext",
            )
        )
        == 2_000
    )
    assert (
        len(text(cursor_context_output("sessionStart", long_text), "additional_context")) == 2_000
    )
    wide = context_output("SessionStart", long_text, limit=RECAP_CONTEXT_LIMIT)
    assert len(text(wide, "hookSpecificOutput", "additionalContext")) == 3_000
