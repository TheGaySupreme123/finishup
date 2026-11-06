"""The application side of claim-bound tasks: portable starts and attested receipts (ADR-051)."""

from __future__ import annotations

from typing import Any, cast

import pytest

import finishup.application.service as service_module
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS,
    CHECK_TIME_CHANGE_UNAVAILABLE_REASONS,
    CLIENT_ATTESTED_OBSERVATION_LINE,
    CLIENT_ATTESTED_WORKSPACE_LINE,
    client_attested_receipt_block,
)
from finishup.ports.control import RepositoryPrivacyContext, WorkspaceLocator
from finishup.ports.workspace_agent import workspace_handle_for_commitment
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import StartRequest

_COMMITMENT = "hmac-sha256:" + "c" * 64
_CLAIM = RepositoryPrivacyContext(_COMMITMENT, "client_claim")
_HANDLE = workspace_handle_for_commitment(_COMMITMENT)
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
    _require(_start(_HANDLE), _CLAIM)
    for reference in (None, "/home/dev/project", "client:fedcba9876543210", "project"):
        with pytest.raises(PublicOperationError) as caught:
            _require(_start(reference), _CLAIM)
        error = caught.value
        assert error.code is PublicErrorCode.INVALID_REQUEST
        assert cast(dict[str, object], error.safe_details)["reason_code"] == (
            "workspace_ref_not_portable"
        )
        assert reference is None or reference not in error.message


def test_only_an_attach_to_an_existing_session_may_omit_the_handle() -> None:
    attach = StartRequest.model_validate(
        {
            **_start(None).model_dump(mode="json", by_alias=True, exclude_none=True),
            "mode": "attach",
            "session_id": "ses_00000000-0000-4000-8000-000000051001",
        }
    )
    _require(attach, _CLAIM)


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
