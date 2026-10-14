"""The host-held check advisory: closed facts in, bounded fixed text out (issue #857)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import cast

import pytest

from yoetz.cli import host_hold_advisory as advisory
from yoetz.cli.hook_io import claude_permission_denied_output


def test_grant_is_confirmed_only_from_a_granted_state_with_llm_inference_enabled() -> None:
    granted = {
        "grant_state": "granted",
        "composed_policy": {"channel_policies": [{"channel": "llm_inference", "enabled": True}]},
    }
    assert advisory.grant_from_setup(granted) == "grant_confirmed"
    assert advisory.grant_from_setup({**granted, "grant_state": "missing"}) == "grant_absent"
    disabled = {
        "grant_state": "granted",
        "composed_policy": {"channel_policies": [{"channel": "llm_inference", "enabled": False}]},
    }
    assert advisory.grant_from_setup(disabled) == "grant_absent"
    # Anything short of both facts is unread, never confirmed and never "absent" either.
    assert advisory.grant_from_setup({"grant_state": "granted"}) == "grant_unread"
    assert advisory.grant_from_setup({**granted, "grant_state": "weird"}) == "grant_unread"
    assert (
        advisory.grant_from_setup(
            {"grant_state": "granted", "composed_policy": {"channel_policies": "not-a-list"}}
        )
        == "grant_unread"
    )
    assert advisory.grant_from_setup(None) == "grant_unread"
    assert advisory.grant_from_setup("granted") == "grant_unread"


def test_retry_ledger_offers_each_session_one_retry_and_stores_only_digests(
    tmp_path: Path,
) -> None:
    assert advisory.note_retry_offer("session-A", _state=tmp_path, _now_ms=10) == "first"
    assert advisory.note_retry_offer("session-A", _state=tmp_path, _now_ms=11) == "repeat"
    assert advisory.note_retry_offer("session-B", _state=tmp_path, _now_ms=12) == "first"
    path = tmp_path / "observation/host-hold-retries.json"
    raw = path.read_bytes()
    assert b"session-A" not in raw and b"session-B" not in raw
    ledger = json.loads(raw)
    assert len(ledger) == 2
    assert all(len(key) == 64 for key in ledger)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "observation").stat().st_mode & 0o777) == "0o700"


def test_retry_ledger_is_bounded_without_forgetting_previous_offers(tmp_path: Path) -> None:
    for index in range(64):
        assert (
            advisory.note_retry_offer(f"session-{index}", _state=tmp_path, _now_ms=index) == "first"
        )
    ledger = json.loads((tmp_path / "observation/host-hold-retries.json").read_bytes())
    assert len(ledger) == 64
    # A full ledger retains old offers and routes new sessions to human approval.
    assert advisory.note_retry_offer("session-0", _state=tmp_path, _now_ms=100) == "repeat"
    assert advisory.note_retry_offer("session-new", _state=tmp_path, _now_ms=101) == "unrecorded"


@pytest.mark.parametrize("content", [b"not json", b"x" * 20_000, b'{"bad-key":1}', b"[]"])
def test_retry_ledger_corruption_never_grants_another_retry(tmp_path: Path, content: bytes) -> None:
    directory = tmp_path / "observation"
    directory.mkdir(mode=0o700)
    path = directory / "host-hold-retries.json"
    path.write_bytes(content)
    path.chmod(0o600)
    assert advisory.note_retry_offer("session-A", _state=tmp_path) == "unrecorded"
    assert path.read_bytes() == content


def test_retry_ledger_does_not_follow_links_or_wait_on_fifo(tmp_path: Path) -> None:
    directory = tmp_path / "observation"
    directory.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.write_bytes(b"{}")
    target.chmod(0o600)
    path = directory / "host-hold-retries.json"
    path.symlink_to(target)
    assert advisory.note_retry_offer("session-A", _state=tmp_path) == "unrecorded"
    assert target.read_bytes() == b"{}" and path.is_symlink()
    path.unlink()
    os.mkfifo(path, 0o600)
    assert advisory.note_retry_offer("session-A", _state=tmp_path) == "unrecorded"


def test_retry_ledger_lock_contention_does_not_block_hook(tmp_path: Path) -> None:
    import fcntl

    directory = tmp_path / "observation"
    directory.mkdir(mode=0o700)
    descriptor = os.open(directory / ".host-hold-retries.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert advisory.note_retry_offer("session-A", _state=tmp_path) == "unrecorded"
    finally:
        os.close(descriptor)


def test_retry_ledger_write_failure_is_reported_not_raised(tmp_path: Path) -> None:
    blocked = tmp_path / "observation"
    blocked.write_text("a file where the directory should be", encoding="utf-8")
    assert advisory.note_retry_offer("session-A", _state=tmp_path, _now_ms=1) == "unrecorded"


def _facts(grant: str, admission: str = "absent") -> advisory.HostHoldFacts:
    return advisory.HostHoldFacts(grant, admission)  # type: ignore[arg-type]


def test_every_composed_advisory_is_bounded_fixed_text_with_closed_tokens_only() -> None:
    cases: list[advisory.HostHoldAdvisory] = []
    for grant in sorted(advisory.GRANT_REASONS):
        for admission in sorted(advisory.ADMISSION_STATES):
            for source in ("auto_mode", None, "permission_rule", "hook", "unexpected"):
                for reason in ("classifier_denied", "no_verdict", None):
                    for offer in ("first", "repeat", "unrecorded"):
                        cases.append(
                            advisory.compose_host_hold_advisory(
                                _facts(grant, admission),
                                source=source,
                                reason=reason,
                                retry_offer=offer,  # type: ignore[arg-type]
                            )
                        )
    assert cases
    for case in cases:
        rendered = claude_permission_denied_output(case.explanation, retry=case.retry)
        specific = rendered["hookSpecificOutput"]
        assert isinstance(specific, dict)
        assert "additionalContext" not in specific
        assert rendered["systemMessage"] == case.explanation
        assert len(case.explanation) <= 2_000
        assert case.explanation.startswith("Yoetz")
        assert "{" not in case.explanation and "}" not in case.explanation
        assert "no provider dispatch occurred" in case.explanation.lower()
        assert "do not switch to deterministic_only" in case.explanation
        # A retry is emitted only with a confirmed grant, a classifier verdict and a first offer.
        if case.retry:
            assert case.diagnostic == "host_denial_retry_offered"
            assert "Retry the identical check exactly once now" in case.explanation
        else:
            assert "exactly once now" not in case.explanation


def test_retry_requires_every_gate() -> None:
    confirmed = _facts("grant_confirmed")
    first = advisory.compose_host_hold_advisory(
        confirmed, source="auto_mode", reason="classifier_denied", retry_offer="first"
    )
    assert first.retry is True and first.diagnostic == "host_denial_retry_offered"
    absent_source = advisory.compose_host_hold_advisory(
        confirmed, source=None, reason="classifier_denied", retry_offer="first"
    )
    assert absent_source.retry is True
    assert (
        advisory.compose_host_hold_advisory(
            confirmed, source="permission_rule", reason="classifier_denied", retry_offer="first"
        ).retry
        is False
    )
    assert (
        advisory.compose_host_hold_advisory(
            confirmed, source="hook", reason="classifier_denied", retry_offer="first"
        ).diagnostic
        == "host_denial_retry_exhausted"
    )
    assert (
        advisory.compose_host_hold_advisory(
            confirmed, source="auto_mode", reason="no_verdict", retry_offer="first"
        ).retry
        is False
    )
    repeat = advisory.compose_host_hold_advisory(
        confirmed, source="auto_mode", reason="classifier_denied", retry_offer="repeat"
    )
    assert repeat.retry is False and repeat.diagnostic == "host_denial_retry_exhausted"
    unrecorded = advisory.compose_host_hold_advisory(
        confirmed, source="auto_mode", reason="classifier_denied", retry_offer="unrecorded"
    )
    assert unrecorded.retry is False and unrecorded.diagnostic == "host_denial_retry_unrecorded"
    for grant in sorted(advisory.GRANT_REASONS - {"grant_confirmed"}):
        unconfirmed = advisory.compose_host_hold_advisory(
            _facts(grant), source="auto_mode", reason="classifier_denied", retry_offer="first"
        )
        assert unconfirmed.retry is False
        assert unconfirmed.diagnostic == "host_denial_grant_unconfirmed"
        assert f"(reason: {grant})" in unconfirmed.explanation


def test_admission_state_steers_the_durable_fix_line() -> None:
    def text(admission: str) -> str:
        return advisory.compose_host_hold_advisory(
            _facts("grant_confirmed", admission),
            source="auto_mode",
            reason="classifier_denied",
            retry_offer="first",
        ).explanation

    assert "yoetz integrate claude admission grant" in text("absent")
    assert "already carries Claude Code's admission entry" in text("present")
    assert "partial Claude Code admission entry" in text("partial")
    assert "wider or conflicting" in text("foreign")
    assert "admission" not in text("unknown").split("gate.")[-1]
    # An unconfirmed grant never advertises admission: that would presuppose the grant.
    unconfirmed = advisory.compose_host_hold_advisory(
        _facts("grant_unread", "absent"),
        source="auto_mode",
        reason="classifier_denied",
        retry_offer="first",
    ).explanation
    assert "admission grant" not in unconfirmed


def test_read_facts_fail_soft_to_closed_unread_tokens(tmp_path: Path) -> None:
    def runner(fn: object) -> object:
        raise RuntimeError("loop unavailable")

    skipped = advisory.read_host_hold_facts(
        str(tmp_path), connect=None, run_async=runner, skip_service=True
    )
    assert skipped.grant == "service_skipped" and skipped.admission_state == "absent"
    unbound = advisory.read_host_hold_facts(None, connect=None, run_async=runner)
    assert unbound.grant == "workspace_unbound" and unbound.admission_state == "unknown"

    async def connect(_kind: object) -> object:
        raise RuntimeError("no service")

    failed = advisory.read_host_hold_facts(
        str(tmp_path), connect=cast(advisory.PrivacyConnector, connect), run_async=runner
    )
    assert failed.grant == "service_unavailable"
    assert not failed.grant_confirmed


def test_claude_permission_denied_output_matches_native_event_schema() -> None:
    # The installed Claude Code 2.1.281 schema admits retry only for this event.
    # additionalContext is supported on other events, but silently dropped here.
    assert claude_permission_denied_output("  shown to the user  ", retry=True) == {
        "hookSpecificOutput": {"hookEventName": "PermissionDenied", "retry": True},
        "systemMessage": "shown to the user",
    }
    assert claude_permission_denied_output("   ", retry=True) == {}
    rendered = claude_permission_denied_output("x" * 2_500, retry=False)
    shown = rendered["systemMessage"]
    assert isinstance(shown, str) and len(shown) == 2_000
    assert shown.endswith("[Yoetz text cut at 2000 characters; read status or the receipt]")


@pytest.mark.parametrize(
    "reason",
    [
        "no_verdict",
        "Classifier unavailable",
        "",
        "Auto mode could not evaluate this action and is blocking it for safety: CANARY",
        None,
    ],
)
def test_current_no_verdict_forms_never_offer_retry(reason: object) -> None:
    assert not advisory.classifier_verdict_present(None, reason)
    result = advisory.compose_host_hold_advisory(
        _facts("grant_confirmed"), source=None, reason=reason, retry_offer="first"
    )
    assert not result.retry
    assert "CANARY" not in result.explanation


@pytest.mark.parametrize("phase", ["connect", "request", "close"])
def test_grant_deadline_bounds_connection_request_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    import asyncio
    from collections.abc import Awaitable, Callable

    import anyio

    monkeypatch.setattr(advisory, "GRANT_READ_DEADLINE_MS", 20)

    class Client:
        async def privacy_get_setup(
            self, request: object, *, deadline_ms: int | None = None
        ) -> object:
            if phase == "request":
                await anyio.sleep_forever()
            return {
                "grant_state": "granted",
                "composed_policy": {
                    "channel_policies": [{"channel": "llm_inference", "enabled": True}]
                },
            }

        async def close(self) -> None:
            if phase == "close":
                await anyio.sleep_forever()

    async def connect(kind: object) -> Client:
        if phase == "connect":
            await anyio.sleep_forever()
        return Client()

    def run(fn: Callable[[], Awaitable[object]]) -> object:
        async def bounded() -> object:
            with anyio.fail_after(1):
                return await fn()

        return asyncio.run(bounded())

    facts = advisory.read_host_hold_facts(str(tmp_path), connect=connect, run_async=run)
    assert facts.grant == "service_unavailable"


@pytest.mark.skipif(os.name != "posix", reason="owner-only modes are POSIX")
def test_retry_ledger_lock_file_is_owner_only(tmp_path: Path) -> None:
    advisory.note_retry_offer("session-A", _state=tmp_path, _now_ms=1)
    lock = tmp_path / "observation/.host-hold-retries.lock"
    assert oct(lock.stat().st_mode & 0o777) == "0o600"


@pytest.mark.parametrize("source", ["unexpected", {}, ["auto_mode"]])
def test_unknown_denial_source_never_authorizes_retry(source: object) -> None:
    result = advisory.compose_host_hold_advisory(
        _facts("grant_confirmed"), source=source, reason="[Rule]", retry_offer="first"
    )
    assert not result.retry


def test_injected_connector_cannot_confirm_an_unbound_repository(tmp_path: Path) -> None:
    def run(fn: object) -> object:
        pytest.fail("unbound repository must not query a grant")

    async def connect(kind: object) -> object:
        pytest.fail("unbound repository must not connect")

    result = advisory.read_host_hold_facts(
        None, connect=cast(advisory.PrivacyConnector, connect), run_async=run
    )
    assert result.grant == "workspace_unbound"
