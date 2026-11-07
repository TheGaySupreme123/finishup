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
    EventSchema,
    IntegrationKind,
    RedactionState,
    RuntimeProfile,
    SessionOpenedPayload,
    UnknownEvent,
)
from finishup.domain.receipts import (
    CHECK_TIME_CHANGE_UNAVAILABLE_REASON_GAPS,
    CHECK_TIME_CHANGE_UNAVAILABLE_REASONS,
    CLIENT_ATTESTED_OBSERVATION_LINE,
    CLIENT_ATTESTED_WORKSPACE_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_LINE,
    WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE,
    client_attested_receipt_block,
    workspace_provenance_unknown_block,
)
from finishup.domain.workspace_provenance import (
    SESSION_OPENING_COPY_UNVERIFIABLE,
    SESSION_OPENING_ERASED,
    SESSION_OPENING_FORMAT_UNKNOWN,
    SESSION_OPENING_KEY_UNAVAILABLE,
    SESSION_OPENING_REDACTED,
    SESSION_OPENING_UNREADABLE,
    WORKSPACE_PROVENANCE_REASONS,
    WorkspaceProvenanceReason,
    workspace_provenance_unknown_lines,
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


def test_a_refusal_says_what_it_now_means_and_where_to_reconnect() -> None:
    """ADR-051 decision 5: listed mode no longer refuses a check-time read (it leaves only the
    unlisted inputs unread, ``outside_reads_not_listed``), so a refusal here is a request the
    agent does not answer, usually a release mismatch. The sentence says so, names the computer
    and the full command, and that checking again can help; it never claims a listed-mode
    refusal or names a path."""

    sentence = CHECK_TIME_CHANGE_UNAVAILABLE_REASONS["workspace_agent_refused"]
    assert "read of the workspace" not in sentence
    assert "same release on both" in sentence
    # Direct dial: the agent session's bridge or the foreground agent serves workspace calls;
    # plain ``server connect`` only makes the connection usable.
    assert "restart the agent session" in sentence
    assert "`finishup server connect NAME --agent`" in sentence
    assert "on the client machine, the computer that holds the project" in sentence
    assert "check again" in sentence
    assert "folders" not in sentence
    assert "/" not in sentence


def test_an_unavailable_agent_names_where_to_reconnect_and_that_a_retry_can_help() -> None:
    sentence = CHECK_TIME_CHANGE_UNAVAILABLE_REASONS["workspace_agent_unavailable"]
    assert "`finishup server status NAME`" in sentence
    assert "keep the agent session open" in sentence
    assert "`finishup server connect NAME --agent` in the project folder" in sentence
    assert "client machine, the computer that holds the project" in sentence
    assert "checking again then can help" in sentence
    assert "/" not in sentence


def test_files_listed_mode_kept_from_review_name_both_ways_out_with_their_arguments() -> None:
    """The fixed line for inputs and declared tests listed mode kept from review (ADR-051
    decision 5): no path and no count, where to run each command, its full arguments, both ways
    out, and that an agent cannot take them."""

    from finishup.domain.receipts import (
        OUTSIDE_READS_NOT_LISTED_GAP,
        OUTSIDE_READS_NOT_LISTED_SHORT_SENTENCE,
        check_time_change_gap_sentence,
    )

    sentence = check_time_change_gap_sentence(OUTSIDE_READS_NOT_LISTED_GAP)
    assert sentence is not None
    for text in (sentence, OUTSIDE_READS_NOT_LISTED_SHORT_SENTENCE):
        assert "`finishup server folders add NAME FOLDER`" in text
        assert "`finishup server folders mode NAME local`" in text
        assert "client machine" in text
        assert "/" not in text and not any(character.isdigit() for character in text)
    assert "the computer that holds the project" in sentence
    assert "listed mode" in sentence and "An agent cannot." in sentence
    assert "Checking again" in sentence
    # Listing a folder never admits a test in the project Git ignores: each way out says which
    # files it covers, so the owner is never sent to a command that cannot help.
    assert "For a file outside the project, list its folder" in sentence
    assert "For a test in the project, listing a folder does not help" in sentence
    assert "stop Git ignoring it" in sentence
    assert "for a file outside the project" in OUTSIDE_READS_NOT_LISTED_SHORT_SENTENCE
    assert "a test in the project that Git ignores" in OUTSIDE_READS_NOT_LISTED_SHORT_SENTENCE


def test_remedy_sentences_name_the_computer_they_concern() -> None:
    """A claim-bound task's Git is the client's, its input roots are the server host's, and a kept
    copy needs its folder readable before the task starts: each sentence says which computer, or
    when, in fixed words (refusal-guide review)."""

    from finishup.domain.receipts import (
        TASK_INPUT_BASELINE_UNAVAILABLE_GAP,
        TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP,
        TASK_INPUT_OUTSIDE_NOT_ADMITTED_SHORT_SENTENCE,
        check_time_change_gap_sentence,
    )

    for reason in ("git_unavailable", "git_version_unsupported"):
        sentence = CHECK_TIME_CHANGE_UNAVAILABLE_REASONS[reason]
        assert "the one the FinishUP service runs on" in sentence
        assert "for a remote server, the client machine that holds the project" in sentence
    admitted = check_time_change_gap_sentence(TASK_INPUT_OUTSIDE_NOT_ADMITTED_GAP)
    assert admitted is not None
    for text in (admitted, TASK_INPUT_OUTSIDE_NOT_ADMITTED_SHORT_SENTENCE):
        assert "`finishup privacy input-roots add <folder>`" in text
        assert "the computer the FinishUP service runs on" in text
        assert "server host" in text
    assert "the folder must exist there" in admitted
    assert "cannot be admitted for a remote server yet" in admitted
    baseline = check_time_change_gap_sentence(TASK_INPUT_BASELINE_UNAVAILABLE_GAP)
    assert baseline is not None and "before the task starts keeps one" in baseline


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

    def __init__(self, records: tuple[object, ...], failure: BaseException | None = None) -> None:
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


_OPENING_ID = "evt_00000000-0000-4000-8000-000000051004"


def _record(payload: object, *, name: str = "session_opened", redaction: str = "present") -> object:
    return SimpleNamespace(
        event_id=_OPENING_ID,
        schema=SimpleNamespace(name=name),
        redaction=RedactionState(redaction),
        payload=payload,
    )


def _opened(workspace_ref: str | None) -> object:
    return _record(
        SessionOpenedPayload(
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
    # Only the session's opening event decides; a later record is never read for it.
    later = _record(None, name="obligation_published")
    assert asyncio.run(attested_by(_runtime(_Ledger((_opened(_HANDLE), later))))) == _INSTANCE


def test_an_opening_event_the_ledger_could_not_read_leaves_the_binding_unknown() -> None:
    """A recovering SQLite ledger keeps a payload object it failed to read as None (finding A6).

    The record is found by its schema name, so its missing payload is never the None that would
    drop a claim-bound receipt's client-attested block. The ledger keeps that gap while it holds
    the task and reads the object again once the service opens the task afresh, so the cause can
    pass: the binding is unknown, and the receipt says to run it again and then restart.
    """

    from builders.replay import genesis_session_opened
    from finishup.application import receipt

    attested_by: Any = getattr(receipt, "_attested_by")
    passing = getattr(receipt, "_Provenance").UNREADABLE
    unread = replace(genesis_session_opened(), payload=None)
    assert unread.redaction is RedactionState.PRESENT
    assert asyncio.run(attested_by(_runtime(_Ledger((unread,))))) is passing
    assert passing.value == SESSION_OPENING_UNREADABLE


def _unknown_version(payload: object) -> UnknownEvent:
    """A ``session_opened`` of a version this service cannot decode, as a ledger returns it.

    Built without the envelope's own validation: only the fields the attestation read looks at
    matter here, and the real ``UnknownEvent`` type is what tells it apart.
    """

    record = object.__new__(UnknownEvent)
    object.__setattr__(record, "schema", EventSchema("session_opened", "9.0.0"))
    object.__setattr__(record, "redaction", RedactionState.PRESENT)
    object.__setattr__(record, "payload", payload)
    return record


def _unknown_version_in(redaction: RedactionState) -> UnknownEvent:
    record = _unknown_version(None)
    object.__setattr__(record, "redaction", redaction)
    return record


@pytest.mark.parametrize(
    ("record", "cause"),
    [
        (_record(None, redaction="logically_redacted"), SESSION_OPENING_REDACTED),
        (_record(None, redaction="erased_claimed"), SESSION_OPENING_ERASED),
        (_record(None, redaction="key_unavailable"), SESSION_OPENING_KEY_UNAVAILABLE),
        # A session_opened version this service cannot decode keeps its raw payload, or None
        # when recovery could not read the object either; reading the object later still leaves
        # a version this service cannot decode.
        (_record({"workspace_ref": _HANDLE}), SESSION_OPENING_FORMAT_UNKNOWN),
        (_unknown_version({"workspace_ref": _HANDLE}), SESSION_OPENING_FORMAT_UNKNOWN),
        (_unknown_version(None), SESSION_OPENING_FORMAT_UNKNOWN),
        # The envelope state holds whatever the version: a redacted record of an unknown version
        # never reads again, even once the server knows its format.
        (_unknown_version_in(RedactionState.LOGICALLY_REDACTED), SESSION_OPENING_REDACTED),
        (_unknown_version_in(RedactionState.ERASED_CLAIMED), SESSION_OPENING_ERASED),
        (_unknown_version_in(RedactionState.KEY_UNAVAILABLE), SESSION_OPENING_KEY_UNAVAILABLE),
    ],
    ids=[
        "logically_redacted",
        "erased_claimed",
        "key_unavailable",
        "unknown_version_payload",
        "unknown_event",
        "unknown_event_unread",
        "unknown_event_redacted",
        "unknown_event_erased",
        "unknown_event_key_unavailable",
    ],
)
def test_an_opening_event_no_retry_can_read_names_its_own_lasting_cause(
    record: object, cause: WorkspaceProvenanceReason
) -> None:
    """A lasting cause: the receipt is built and its last line says why that cause lasts, never
    that a retry or a restart would help, and never what is true only of another cause."""

    from finishup.application import receipt

    attested_by: Any = getattr(receipt, "_attested_by")
    lasting = getattr(receipt, "_Provenance")(cause)
    assert asyncio.run(attested_by(_runtime(_Ledger((record,))))) is lasting
    assert lasting.value == cause
    assert cause != SESSION_OPENING_UNREADABLE


def test_an_opening_whose_payload_did_not_load_is_a_passing_cause() -> None:
    from finishup.application import receipt

    attested_by: Any = getattr(receipt, "_attested_by")
    passing = getattr(receipt, "_Provenance").UNREADABLE
    assert asyncio.run(attested_by(_runtime(_Ledger((_record(None),))))) is passing


class _CheckedLedger(_Ledger):
    """A task ledger that also reports which payload objects failed verification at recovery."""

    def __init__(self, records: tuple[object, ...], answer: object) -> None:
        super().__init__(records)
        self._answer = answer
        self.asked: list[str] = []

    async def payload_object_unverifiable(self, event_id: str) -> object:
        self.asked.append(event_id)
        if isinstance(self._answer, BaseException):
            raise self._answer
        return self._answer


def test_an_opening_whose_stored_copy_failed_verification_is_its_own_lasting_cause() -> None:
    """Decision D4b: the object store refuses a missing or corrupt payload object as its
    deterministic ``object_verification_failed``, and the ledger keeps that fact. Opening the task
    again reads the same bytes, so the receipt says why it lasts, never to restart."""

    from finishup.application import receipt

    attested_by: Any = getattr(receipt, "_attested_by")
    provenance = getattr(receipt, "_Provenance")
    ledger = _CheckedLedger((_record(None),), True)
    answer = asyncio.run(attested_by(_runtime(ledger)))
    assert answer is provenance.COPY_UNVERIFIABLE
    assert answer.value == SESSION_OPENING_COPY_UNVERIFIABLE
    assert ledger.asked == [_OPENING_ID]
    # An object that did not load for any other reason (an environmental fault) can pass.
    ledger = _CheckedLedger((_record(None),), False)
    assert asyncio.run(attested_by(_runtime(ledger))) is provenance.UNREADABLE
    assert ledger.asked == [_OPENING_ID]


@pytest.mark.parametrize(
    ("record", "cause"),
    [
        (_record(None, redaction="logically_redacted"), SESSION_OPENING_REDACTED),
        (_record(None, redaction="key_unavailable"), SESSION_OPENING_KEY_UNAVAILABLE),
        (_unknown_version(None), SESSION_OPENING_FORMAT_UNKNOWN),
    ],
    ids=["logically_redacted", "key_unavailable", "unknown_event_unread"],
)
def test_only_a_decodable_present_opening_asks_whether_its_copy_failed_verification(
    record: object, cause: WorkspaceProvenanceReason
) -> None:
    """The envelope state and the version decide first: a redacted record or one this version
    cannot decode names that cause even when its payload object is also unverifiable."""

    from finishup.application import receipt

    attested_by: Any = getattr(receipt, "_attested_by")
    ledger = _CheckedLedger((record,), True)
    assert asyncio.run(attested_by(_runtime(ledger))) is getattr(receipt, "_Provenance")(cause)
    assert ledger.asked == []
    read = _CheckedLedger((_opened(_HANDLE),), True)
    assert asyncio.run(attested_by(_runtime(read))) == _INSTANCE
    assert read.asked == []


@pytest.mark.parametrize(
    "answer",
    [OSError(5, "input/output error"), RuntimeError("ledger_unavailable"), "yes", 1, None],
    ids=["os_error", "other_error", "not_a_bool", "truthy_int", "none"],
)
def test_an_unestablished_stored_copy_fact_stays_a_passing_cause(
    answer: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only an explicit True is a lasting claim. A failing lookup is recorded as one bounded
    diagnostic and never refuses the receipt; anything else is not established, so it can pass."""

    from finishup.application import receipt

    recorded = _Recorded()
    monkeypatch.setattr(receipt, "record_classified_exception_without_raising", recorded)
    attested_by: Any = getattr(receipt, "_attested_by")
    request_id = "req_00000000-0000-4000-8000-000000051005"
    answered = asyncio.run(
        attested_by(_runtime(_CheckedLedger((_record(None),), answer)), request_id=request_id)
    )
    assert answered is getattr(receipt, "_Provenance").UNREADABLE
    expected = (
        [
            (
                type(answer),
                {
                    "component": "application.receipt",
                    "operation": "receipt_attestation_read",
                    "request_id": request_id,
                },
            )
        ]
        if isinstance(answer, BaseException)
        else []
    )
    assert recorded.calls == expected


def test_a_cancelled_stored_copy_lookup_is_never_turned_into_an_answer() -> None:
    from finishup.application import receipt

    attested_by: Any = getattr(receipt, "_attested_by")
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            attested_by(_runtime(_CheckedLedger((_record(None),), asyncio.CancelledError())))
        )


@pytest.mark.parametrize("reason", WORKSPACE_PROVENANCE_REASONS)
@pytest.mark.parametrize("markdown", [False, True])
def test_the_unknown_provenance_block_is_fixed_words(
    markdown: bool, reason: WorkspaceProvenanceReason
) -> None:
    """Decision D4: what happened, why it matters, and what to do for the passing cause or why
    that cause lasts, in fixed words only."""

    heading = "## Workspace evidence" if markdown else "Workspace evidence"
    block = workspace_provenance_unknown_block(markdown=markdown, reason=reason)
    assert block.splitlines() == [heading, *workspace_provenance_unknown_lines(reason)]
    assert block.splitlines()[1:3] == [
        WORKSPACE_PROVENANCE_UNKNOWN_LINE,
        WORKSPACE_PROVENANCE_UNKNOWN_IMPACT_LINE,
    ]
    if reason == SESSION_OPENING_UNREADABLE:
        assert block.endswith("\n" + WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE)
    else:
        # A lasting cause gives no retry or restart advice.
        assert WORKSPACE_PROVENANCE_UNKNOWN_RETRY_LINE not in block
        assert "finishup service restart" not in block
        assert block.splitlines()[-1].startswith("Why it lasts: ")
    # Nothing in any section says the evidence was read on the client: it says that is unknown.
    assert CLIENT_ATTESTED_WORKSPACE_LINE not in block


def test_the_passing_section_is_the_fixed_retry_words() -> None:
    assert workspace_provenance_unknown_lines(SESSION_OPENING_UNREADABLE) == (
        "Provenance unknown: the record of how this task's session was opened could not be "
        "read from the server's ledger.",
        "Why it matters: FinishUP cannot confirm whether this task's workspace evidence was "
        "read on the client machine.",
        "What to do: run receipt again. If this persists, restart the server's FinishUP service "
        "(`finishup service restart` on the server host), then run receipt again.",
    )


@pytest.mark.parametrize(
    "reason", ["session_opening_lost", "session_opening_unrecoverable", "", None]
)
def test_the_unknown_provenance_block_admits_only_a_closed_reason(reason: object) -> None:
    from finishup.protocol.errors import ProtocolValueError

    with pytest.raises(ProtocolValueError, match="invalid_receipt_document"):
        workspace_provenance_unknown_block(markdown=False, reason=cast(Any, reason))


class _Recorded:
    """Captures the bounded diagnostics the attestation read records instead of refusing."""

    def __init__(self) -> None:
        self.calls: list[tuple[type[BaseException], dict[str, object]]] = []

    def __call__(self, exc: BaseException, **fields: object) -> str:
        self.calls.append((type(exc), fields))
        return "cor_00000000-0000-4000-8000-000000051003"


@pytest.mark.parametrize(
    "failure",
    [
        OSError(5, "input/output error"),
        ValueError("ledger_chain_invalid"),
        KeyError("object_missing"),
        PublicOperationError(PublicErrorCode.STORAGE_CORRUPT, "The ledger is unreadable.", False),
        PublicOperationError(PublicErrorCode.STORAGE_UNSAFE, "The ledger is unavailable.", True),
        RuntimeError("ledger_unavailable"),
    ],
    ids=["os_error", "malformed", "missing", "classified_corrupt", "classified_unsafe", "other"],
)
def test_a_failed_attestation_read_leaves_the_binding_unknown_and_never_refuses(
    failure: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Decision D4: the receipt is built and says the provenance is unknown; nothing refuses.

    The failure is recorded as one bounded diagnostic under ``receipt_attestation_read`` so an
    operator can find it; the caller gets the unknown binding, never an error. Nothing can tell a
    passing read failure from a lasting one, so it is never called lasting: the receipt says to
    run it again and then restart.
    """

    from finishup.application import receipt

    recorded = _Recorded()
    monkeypatch.setattr(receipt, "record_classified_exception_without_raising", recorded)
    attested_by: Any = getattr(receipt, "_attested_by")
    unknown = getattr(receipt, "_Provenance").UNREADABLE
    request_id = "req_00000000-0000-4000-8000-000000051002"
    for records in ((), (_record(None, name="session_resumed"),)):
        recorded.calls.clear()
        answer = asyncio.run(
            attested_by(_runtime(_Ledger(records, failure)), request_id=request_id)
        )
        assert answer is unknown
        assert recorded.calls == [
            (
                type(failure),
                {
                    "component": "application.receipt",
                    "operation": "receipt_attestation_read",
                    "request_id": request_id,
                },
            )
        ]


def test_a_failed_attestation_read_recovers_on_the_next_read() -> None:
    """The next receipt or replay reads the opening again, so a cleared fault restores it."""

    from finishup.application import receipt

    attested_by: Any = getattr(receipt, "_attested_by")
    unknown = getattr(receipt, "_Provenance").UNREADABLE
    ledger = _Ledger((), OSError(5, "input/output error"))
    runtime = _runtime(ledger)
    assert asyncio.run(attested_by(runtime)) is unknown
    runtime.ledger = _Ledger((_opened(_HANDLE),))
    assert asyncio.run(attested_by(runtime)) == _INSTANCE


def test_a_cancelled_attestation_read_is_never_turned_into_an_answer() -> None:
    from finishup.application import receipt

    attested_by: Any = getattr(receipt, "_attested_by")
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(attested_by(_runtime(_Ledger((), asyncio.CancelledError()))))
