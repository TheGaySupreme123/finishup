"""Start-first flow over the real composition: continuation, ceremony, exact replay (#512).

The 2026-08-31 issue #334 dogfood: an installed agent followed the required start-first workflow
against a pristine install, received a bare non-retryable ``VAULT_LOCKED``, and correctly stopped
before any task existed. These tests run the whole sanctioned flow end to end over the real
daemon, real MCP bridge dispatch, and the real agent-authorized initialization ceremony: the
first `start` answers with the typed ``vault_initialization_required`` continuation, the exact
approved ceremony initializes the vault, and replaying the exact original `start` request id and
body mints a real session without inventing new identity. Denial stays a distinct bounded
outcome, leaves no credential behind, and the continuation remains available.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

import finishup.mcp.server as bridge
from finishup.cli import elevated
from finishup.protocol.canonical import JsonValue
from finishup.service.elevated_bootstrap import load_pending
from integration.service.test_consent_vault_initialize_composition import (
    _approve_attestation,  # pyright: ignore[reportPrivateUsage]
    _approved_store,  # pyright: ignore[reportPrivateUsage]
    _assert_no_secret_bytes,  # pyright: ignore[reportPrivateUsage]
    _entry_bytes,  # pyright: ignore[reportPrivateUsage]
    _MemoryKeyring,  # pyright: ignore[reportPrivateUsage]
    _production_daemon,  # pyright: ignore[reportPrivateUsage]
    _slot_accounts,  # pyright: ignore[reportPrivateUsage]
    runtime_directory,  # noqa: F401 - imported pytest fixture  # pyright: ignore[reportUnusedImport]
)

_REQUEST = "req_00000000-0000-4000-8000-000000000512"

_EXPECTED_CONTINUATION = {
    "authorize_command": "finishup consent authorize",
    "continuation": "vault_initialization_required",
    "pending_ttl_seconds": 900,
    "prepare_command": "finishup consent prepare vault_initialize",
    "replay_request_id": _REQUEST,
    "review_command": "finishup consent review",
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _start_body() -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": _REQUEST,
        "actor": {"actor_id": "harness:composition-512", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "mode": "create",
        "task_title": "First task on a pristine install",
        "requested_view": "compact",
    }


def _error(result: object) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    assert getattr(result, "isError") is True
    return cast(dict[str, object], structured["error"])


@pytest.mark.anyio
async def test_start_first_flow_reaches_a_session_through_initialization_and_exact_replay(
    tmp_path: Path,
    runtime_directory: Path,  # noqa: F811 - imported pytest fixture
) -> None:
    tmp_path.chmod(0o700)
    consent_state = tmp_path / "consent"
    consent_state.mkdir(mode=0o700)
    backend = _MemoryKeyring()
    store = _approved_store(tmp_path / "data", backend)
    active_account, _staged_account = _slot_accounts(store)

    daemon = await _production_daemon(tmp_path, pristine=True)
    await daemon.start()
    serving = asyncio.create_task(daemon.serve())
    runtime = bridge.build_bridge_runtime()
    try:
        # 1. The natural start-first call answers with the typed continuation, not a dead end.
        first = _error(await bridge.dispatch_start(_start_body(), runtime))
        assert first["code"] == "VAULT_LOCKED"
        assert first["retryable"] is False
        assert first["safe_details"] == _EXPECTED_CONTINUATION
        assert "bounded initialization-required continuation" in cast(str, first["message"])
        assert daemon.status().vault_mode == "uninitialized"

        # 2. The exact user decision: prepare, present, approve via the sanctioned ceremony.
        with (
            patch("finishup.service.elevated_bootstrap.state_dir", return_value=consent_state),
            patch("finishup.cli.elevated._auto_unlock_store", return_value=store),
        ):
            elevated.prepare_elevated("vault_initialize")
            pending = load_pending(_state=consent_state)
            assert pending is not None
            result = await asyncio.wait_for(
                elevated.authorize_elevated(_approve_attestation(pending)), timeout=30
            )
        assert result["outcome"] == "completed"
        assert result["result"] == {"state": "ready", "reason": "succeeded"}
        assert daemon.status().vault_mode == "passphrase"

        # 3. Replay the exact original request id and body: a real session, same identity.
        replayed = await bridge.dispatch_start(_start_body(), runtime)
        assert getattr(replayed, "isError") is not True
        structured = cast(dict[str, object], getattr(replayed, "structuredContent"))
        assert structured["ok"] is True
        assert structured["request_id"] == _REQUEST
        assert cast(str, structured["session_id"]).startswith("ses_")
        assert cast(str, structured["task_id"]).startswith("tsk_")
    finally:
        await bridge.close_bridge_runtime(runtime)
        await daemon.stop()
        await asyncio.wait_for(serving, timeout=10)

    # No secret or recovery material reached the bridge, ledger, consent state, or sockets dir.
    secret = _entry_bytes(backend, active_account)
    _assert_no_secret_bytes(tmp_path, secret)
    _assert_no_secret_bytes(runtime_directory, secret)


@pytest.mark.anyio
async def test_denied_initialization_is_bounded_and_the_continuation_remains(
    tmp_path: Path,
    runtime_directory: Path,  # noqa: F811 - imported pytest fixture
) -> None:
    tmp_path.chmod(0o700)
    consent_state = tmp_path / "consent"
    consent_state.mkdir(mode=0o700)
    backend = _MemoryKeyring()
    store = _approved_store(tmp_path / "data", backend)

    daemon = await _production_daemon(tmp_path, pristine=True)
    await daemon.start()
    serving = asyncio.create_task(daemon.serve())
    runtime = bridge.build_bridge_runtime()
    try:
        first = _error(await bridge.dispatch_start(_start_body(), runtime))
        assert first["safe_details"] == _EXPECTED_CONTINUATION

        with (
            patch("finishup.service.elevated_bootstrap.state_dir", return_value=consent_state),
            patch("finishup.cli.elevated._auto_unlock_store", return_value=store),
        ):
            elevated.prepare_elevated("vault_initialize")
            pending = load_pending(_state=consent_state)
            assert pending is not None
            attestation = _approve_attestation(pending)
            attestation["decision"] = "deny"
            denied = await asyncio.wait_for(elevated.authorize_elevated(attestation), timeout=30)
            assert denied["outcome"] == "denied"
            assert load_pending(_state=consent_state) is None

        # Denial is a distinct bounded outcome: nothing initialized, nothing staged or stranded.
        assert daemon.status().vault_mode == "uninitialized"
        assert backend.values == {}
        assert not (tmp_path / "data" / "vault").exists()

        # The flow remains recoverable: a later attempt still receives the exact continuation.
        again = _error(await bridge.dispatch_start(_start_body(), runtime))
        assert again["code"] == "VAULT_LOCKED"
        assert again["safe_details"] == _EXPECTED_CONTINUATION
    finally:
        await bridge.close_bridge_runtime(runtime)
        await daemon.stop()
        await asyncio.wait_for(serving, timeout=10)
