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
