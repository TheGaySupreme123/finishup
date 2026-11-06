"""The application side of claim-bound tasks: portable starts and attested receipts (ADR-051)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

import finishup.application.service as service_module
from finishup.domain.events import (
    ClientKind,
    IntegrationKind,
    RuntimeProfile,
    SessionOpenedPayload,
)
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS,
    CHECK_TIME_CHANGE_UNAVAILABLE_REASONS,
    CLIENT_ATTESTED_OBSERVATION_LINE,
    CLIENT_ATTESTED_WORKSPACE_LINE,
    client_attested_receipt_block,
)
from finishup.ports.control import RepositoryPrivacyContext, WorkspaceLocator
from finishup.ports.workspace_agent import workspace_handle_for_claim
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import StartRequest

_COMMITMENT = "hmac-sha256:" + "c" * 64
_HANDLE = workspace_handle_for_claim(_COMMITMENT, "sha256:" + "a1" * 32)
_CLAIM = RepositoryPrivacyContext(_COMMITMENT, "client_claim", workspace_handle=_HANDLE)
_INSTANCE = "svc_00000000-0000-4000-8000-000000000051"

_require: Any = getattr(service_module, "_require_portable_workspace_ref")


def _start(workspace_ref: str | None) -> StartRequest:
    body: dict[str, object] = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000051001",
        "mode": "create",
        "task_title": "Portable start",
        "actor": {"actor_id": "harness:pytest", "actor_type": "harness"},
        "client": {"kind": "codex_cli", "version": "0.1.0", "integration": "local_cli"},
        "requested_view": "compact",
    }
    if workspace_ref is not None:
        body["workspace_ref"] = workspace_ref
        body["external_ref"] = "portable"
    return StartRequest.model_validate(body)


def test_a_claim_bound_connection_reads_only_its_handle() -> None:
    assert service_module.context_workspace(_CLAIM) == _HANDLE
    assert service_module.context_workspace(None) is None
    local = RepositoryPrivacyContext(
        "hmac-sha256:" + "d" * 64, "git_common_root", WorkspaceLocator("/work/repo")
    )
    assert service_module.context_workspace(local) == "/work/repo"
    assert (
        service_module.context_workspace(
            RepositoryPrivacyContext("hmac-sha256:" + "d" * 64, "git_common_root")
        )
        is None
    )


def test_a_claim_bound_start_records_only_its_own_handle() -> None:
    assert _require(_start(_HANDLE), _CLAIM) is None
    for reference in ("/srv/dev/project", "client:fedcba9876543210", "project"):
        with pytest.raises(PublicOperationError) as caught:
            _require(_start(reference), _CLAIM)
        error = caught.value
        assert error.code is PublicErrorCode.INVALID_REQUEST
        assert cast(dict[str, object], error.safe_details)["reason_code"] == (
            "workspace_ref_not_portable"
        )
        assert reference not in error.message


def test_another_worktree_of_the_repository_is_another_workspace() -> None:
    """Linked worktrees share the repository's commitment, never a workspace handle."""

    other = workspace_handle_for_claim(_COMMITMENT, "sha256:" + "b2" * 32)
    sibling = RepositoryPrivacyContext(_COMMITMENT, "client_claim", workspace_handle=other)
    assert other != _HANDLE and sibling.commitment == _CLAIM.commitment
    assert service_module.context_workspace(sibling) == other
    _require(_start(other), sibling)
    with pytest.raises(PublicOperationError) as caught:
        _require(_start(_HANDLE), sibling)
    assert cast(dict[str, object], caught.value.safe_details)["reason_code"] == (
        "workspace_ref_not_portable"
    )


def _variant(**changes: object) -> StartRequest:
    return StartRequest.model_validate(
        {**_start(None).model_dump(mode="json", by_alias=True, exclude_none=True), **changes}
    )


_SESSION = "ses_00000000-0000-4000-8000-000000051001"
_NAMING_NONE = {
    "create": {},
    "create_or_attach": {"mode": "create_or_attach"},
    "parent_registered": {"parent_session_id": _SESSION},
    "attach": {"mode": "attach", "session_id": _SESSION},
    "delegate": {"mode": "delegate", "session_id": _SESSION},
}


@pytest.mark.parametrize("changes", _NAMING_NONE.values(), ids=_NAMING_NONE.keys())
def test_a_start_naming_no_workspace_opens_any_session_on_the_connections_handle(
    changes: dict[str, object],
) -> None:
    # On one computer such a start reads the connection's own locator path. A claim names the
    # same workspace, so any session the start opens records the handle and its receipts say
    # so; a start that opens none (an attach, a delegation) never reads it.
    assert _require(_variant(**changes), _CLAIM) == _HANDLE


@pytest.mark.parametrize("changes", _NAMING_NONE.values(), ids=_NAMING_NONE.keys())
def test_a_start_naming_no_workspace_is_unchanged_without_a_claim(
    changes: dict[str, object],
) -> None:
    local = RepositoryPrivacyContext(
        "hmac-sha256:" + "d" * 64, "git_common_root", WorkspaceLocator("/work/repo")
    )
    for context in (local, None):
        assert _require(_variant(**changes), context) is None


def test_a_connection_without_a_claim_cannot_record_a_handle() -> None:
    local = RepositoryPrivacyContext(
        "hmac-sha256:" + "d" * 64, "git_common_root", WorkspaceLocator("/work/repo")
    )
    _require(_start("/work/repo"), local)
    _require(_start("my-project"), None)
    for context in (local, None):
        with pytest.raises(PublicOperationError) as caught:
            _require(_start(_HANDLE), context)
        assert cast(dict[str, object], caught.value.safe_details)["reason_code"] == (
            "workspace_binding_conflict"
        )


def test_the_attested_block_is_fixed_words_and_the_serving_instance() -> None:
    text = client_attested_receipt_block(_INSTANCE, markdown=False)
    markdown = client_attested_receipt_block(_INSTANCE, markdown=True)
    assert text.splitlines() == [
        "Workspace evidence",
        CLIENT_ATTESTED_WORKSPACE_LINE,
        f"Served by FinishUP service {_INSTANCE} (connection: client_claim).",
    ]
    assert markdown.splitlines()[0] == "## Workspace evidence"
    with pytest.raises(ValueError):
        client_attested_receipt_block("dev.example.com", markdown=False)


def test_hook_observed_evidence_adds_the_fixed_client_attested_observation_line() -> None:
    """ADR-051 decision 12: the client's consent and commitments were not verified here."""

    observed = client_attested_receipt_block(_INSTANCE, markdown=True, hook_observed=True)
    assert observed.splitlines() == [
        "## Workspace evidence",
        CLIENT_ATTESTED_WORKSPACE_LINE,
        CLIENT_ATTESTED_OBSERVATION_LINE,
        f"Served by FinishUP service {_INSTANCE} (connection: client_claim).",
    ]
    assert "/" not in CLIENT_ATTESTED_OBSERVATION_LINE
    assert "did not verify" in CLIENT_ATTESTED_OBSERVATION_LINE


def test_an_unanswered_agent_is_a_closed_check_time_change_gap() -> None:
    sentence = CHECK_TIME_CHANGE_UNAVAILABLE_REASONS["workspace_agent_unavailable"]
    assert "workspace agent" in sentence and "/" not in sentence
    assert (
        "check_time_change_unavailable_workspace_agent_unavailable"
        in CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS
    )


@pytest.mark.parametrize(
    ("hub_reason", "agent_reason", "gap_reason"),
    [
        ("agent_refused", "workspace_not_claimed", "workspace_agent_refused"),
        ("operation_not_declared", None, "workspace_agent_refused"),
        ("agent_failed", "internal_error", "workspace_agent_unavailable"),
        ("agent_unavailable", "workspace_unavailable", "workspace_agent_unavailable"),
        ("no_agent", None, "workspace_agent_unavailable"),
        ("agent_disconnected", None, "workspace_agent_unavailable"),
        ("deadline_exceeded", None, "workspace_agent_unavailable"),
        ("reply_invalid", None, "workspace_agent_unavailable"),
    ],
)
def test_an_agent_refusal_and_an_agent_loss_are_named_apart(
    hub_reason: str, agent_reason: str | None, gap_reason: str
) -> None:
    """A receipt never says the agent was silent when it refused, nor refused when it failed."""

    from finishup.application import check_change
    from finishup.ports.workspace_agent import WorkspaceAgentUnavailable

    loss = WorkspaceAgentUnavailable(hub_reason, agent_reason)
    reason = check_change._agent_loss_reason(loss)  # pyright: ignore[reportPrivateUsage]
    assert reason == gap_reason
    sentence = CHECK_TIME_CHANGE_UNAVAILABLE_REASONS[reason]
    assert "/" not in sentence
    assert ("refused" in sentence) is (gap_reason == "workspace_agent_refused")
    assert "check_time_change_unavailable_" + reason in CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS


def test_both_agent_gaps_are_classified_beside_their_siblings() -> None:
    from finishup.kernel.gap_effect import GAP_EFFECT_TABLE, PROOF_TOLERATED_GAPS

    for reason in ("workspace_agent_unavailable", "workspace_agent_refused"):
        code = "check_time_change_unavailable_" + reason
        assert code in GAP_EFFECT_TABLE
        assert code in PROOF_TOLERATED_GAPS
        sibling = GAP_EFFECT_TABLE["check_time_change_unavailable_capture_failed"]
        assert replace(GAP_EFFECT_TABLE[code], code=sibling.code) == sibling


class _Ledger:
    """A task ledger whose event read yields ``records`` and then fails with ``failure``."""

    def __init__(self, records: tuple[object, ...], failure: Exception | None = None) -> None:
        self._records = records
        self._failure = failure

    async def load_events(self, session_id: str) -> AsyncIterator[object]:
        del session_id
        for record in self._records:
            yield record
        if self._failure is not None:
            raise self._failure


def _runtime(ledger: _Ledger) -> Any:  # noqa: ANN401
    return SimpleNamespace(
        ledger=ledger,
        session_id="ses_00000000-0000-4000-8000-000000000051",
        fence=SimpleNamespace(service_instance_id=_INSTANCE),
    )


def _opened(workspace_ref: str | None) -> object:
    return SimpleNamespace(
        payload=SessionOpenedPayload(
            task_title="Remote task",
            client_kind=ClientKind.TEST_CLIENT,
            client_version="0.1.0",
            integration=IntegrationKind.LOCAL_CLI,
            profile=RuntimeProfile.TEST_FAKE,
            workspace_ref=workspace_ref,
        )
    )


def test_the_attestation_reads_the_session_opening_and_none_means_not_claim_bound() -> None:
    from finishup.application import receipt

    attested_by: Any = getattr(receipt, "_attested_by")
    assert asyncio.run(attested_by(_runtime(_Ledger((_opened(_HANDLE),))))) == _INSTANCE
    assert asyncio.run(attested_by(_runtime(_Ledger((_opened("/srv/project"),))))) is None
    assert asyncio.run(attested_by(_runtime(_Ledger(())))) is None


@pytest.mark.parametrize(
    ("failure", "code", "retryable"),
    [
        (OSError(5, "input/output error"), PublicErrorCode.STORAGE_UNSAFE, True),
        (ValueError("ledger_chain_invalid"), PublicErrorCode.STORAGE_CORRUPT, False),
    ],
)
def test_a_failed_attestation_read_is_a_storage_error_never_an_unattested_receipt(
    failure: Exception, code: PublicErrorCode, retryable: bool
) -> None:
    """A claim-bound receipt would otherwise render without its client-attested block."""

    from finishup.application import receipt

    attested_by: Any = getattr(receipt, "_attested_by")
    with pytest.raises(PublicOperationError) as raised:
        asyncio.run(
            attested_by(
                _runtime(_Ledger((), failure)),
                request_id="req_00000000-0000-4000-8000-000000051002",
            )
        )
    assert raised.value.code is code
    assert raised.value.retryable is retryable
