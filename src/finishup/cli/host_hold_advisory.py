"""Advisory for an AI-powered ``check`` that a host's automatic reviewer held (issue #857).

Claude Code's ``PermissionDenied`` hook fires after auto mode denies a tool call. Until this module the FinishUP hook recorded one payload-free diagnostic
and said nothing, so the agent saw only the host's fixed refusal text and routinely downgraded a
review the owner had already authorized in the trusted privacy ceremony (issues #187, #467).

This module composes what the hook may say and do about that hold. It states FinishUP's own
first-hand facts — whether the repository grant permits external AI-powered review, read from the
running service inside the hook deadline, and the host's project-scoped admission state — and it
offers the host's documented ``retry`` exactly once per session. It never emits an allow
decision, never edits host configuration, and never asserts a grant it did not read: an
unreadable grant is ``grant_unread``, never confirmed. The host's own permission flow and the
human remain the authority (ADR-018).

Every rendered text is a fixed constant or a composition of closed tokens. No tool input,
reason prose, path, session id, or model output is echoed.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import tempfile
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Protocol, cast

import anyio

from finishup.config.paths import ensure_owner_only_dir, state_dir
from finishup.domain.values import JsonObject
from finishup.ports.control import ControlClientKind, ControlError

try:
    import fcntl
except ImportError:  # pragma: no cover - supported hook hosts are POSIX
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "ADMISSION_STATES",
    "GRANT_READ_DEADLINE_MS",
    "GRANT_REASONS",
    "GrantReadReason",
    "HostHoldAdvisory",
    "HostHoldFacts",
    "PrivacyConnector",
    "RetryOfferOutcome",
    "classifier_verdict_present",
    "compose_host_hold_advisory",
    "grant_from_setup",
    "note_retry_offer",
    "read_host_hold_facts",
    "read_repository_grant",
    "read_admission_state",
]

type GrantReadReason = Literal[
    "grant_confirmed",
    "grant_absent",
    "grant_unread",
    "service_unavailable",
    "vault_locked",
    "privacy_authority_required",
    "service_skipped",
    "workspace_unbound",
]
type RetryOfferOutcome = Literal["first", "repeat", "unrecorded"]

# The privacy read must fit inside the rendered 5 s PermissionDenied hook timeout together with
# process start, the admission file read, and the stdout write.
GRANT_READ_DEADLINE_MS: Final = 2_500
_RETRY_FILE_NAME: Final = "host-hold-retries.json"
_RETRY_LOCK_NAME: Final = ".host-hold-retries.lock"
_MAX_RETRY_ENTRIES: Final = 64
_MAX_RETRY_FILE_BYTES: Final = 16 * 1024
_RETRY_KEY_DOMAIN: Final = b"yoetz/host-hold-retry/v1\x00"
ADMISSION_STATES: Final = frozenset({"absent", "present", "partial", "foreign", "unknown"})
GRANT_REASONS: Final = frozenset(
    {
        "grant_confirmed",
        "grant_absent",
        "grant_unread",
        "service_unavailable",
        "vault_locked",
        "privacy_authority_required",
        "service_skipped",
        "workspace_unbound",
    }
)

_ADMISSION_COMMAND: Final = "finishup integrate claude admission grant"
_PRIVACY_COMMAND: Final = "finishup --privacy"

# --- User-visible explanations. PermissionDenied does not support additionalContext.

_CONFIRMED_PREFIX: Final = (
    "FinishUP confirms: the repository owner already authorized external AI-powered review for this "
    "repository through the trusted FinishUP privacy ceremony (repository grant present, external "
    "review permitted). Claude Code's automatic reviewer held this check; FinishUP did not, and no "
    "provider dispatch occurred for this denied invocation. The MCP route and all remaining "
    "FinishUP gates still apply."
)
_CONFIRMED_RETRY: Final = (
    " Retry the identical check exactly once now: same request body and request_id. If the host "
    "holds it again, stop and present that exact call for the user's approval and wait."
)
_CONFIRMED_NO_RETRY: Final = (
    " Do not retry on your own: stop and present this exact check (same request body and "
    "request_id) for the user's approval and wait."
)
_CONFIRMED_NO_VERDICT: Final = (
    " A classifier verdict was not established for this call, so no retry is offered: "
    "stop and present this exact check (same request body and request_id) for the user's "
    "approval and wait."
)
_PENDING_RULES: Final = (
    " While that decision is pending do not switch to deterministic_only, do not open a new "
    "semantic job, and do not claim completion or request a final receipt. Host approval permits "
    "the tool call only; FinishUP still enforces every privacy, disclosure, and credential gate."
)
_RULE_HELD: Final = (
    "FinishUP: the owner's own Claude Code permission rule or another hook held this AI-powered "
    "check, not the auto-mode classifier. Do not retry. Present this exact check (same request "
    "body and request_id) for the user's decision and wait. No provider dispatch occurred for this denied invocation."
    + _PENDING_RULES
)
_UNCONFIRMED_PREFIX: Final = (
    "FinishUP could not confirm a repository grant for external AI-powered review for this "
    "repository (reason: {reason}). Authorization remains unconfirmed: do not retry on your own. "
    "Present this exact check (same request body and request_id) for the user's decision and "
    "wait. No provider dispatch occurred for this denied invocation."
)
_ADMISSION_NOTES: Final[Mapping[str, str]] = {
    "absent": (
        " Durable fix for the owner, outside this chat: '"
        + _ADMISSION_COMMAND
        + "' writes Claude Code's own allow rule for exactly check."
    ),
    "present": (
        " This repository already carries Claude Code's admission entry for check, yet the host "
        "held the call; the owner should confirm Claude Code trusts this folder's local settings."
    ),
    "partial": (
        " This repository carries a partial Claude Code admission entry for check; the owner can "
        "complete it with '" + _ADMISSION_COMMAND + "'."
    ),
    "foreign": (
        " A wider or conflicting Claude Code permission rule for check exists in this "
        "repository; the owner should review .claude/settings.local.json."
    ),
    "unknown": "",
}
_GRANT_ABSENT_NOTE: Final = (
    " The owner can authorize external review for this repository with '" + _PRIVACY_COMMAND + "'."
)


class _PrivacyClient(Protocol):
    async def privacy_get_setup(
        self, request: JsonObject, *, deadline_ms: int | None = None
    ) -> object: ...

    async def close(self) -> None: ...


type PrivacyConnector = Callable[[ControlClientKind], Awaitable[_PrivacyClient]]
type AsyncRunner = Callable[[Callable[[], Awaitable[object]]], object]


@dataclass(frozen=True, slots=True)
class HostHoldFacts:
    """FinishUP's first-hand facts about one held check; every field is a closed token."""

    grant: GrantReadReason
    admission_state: str

    @property
    def grant_confirmed(self) -> bool:
        return self.grant == "grant_confirmed"


@dataclass(frozen=True, slots=True)
class HostHoldAdvisory:
    """What the hook says and does about one held check."""

    explanation: str
    retry: bool
    diagnostic: Literal[
        "host_denial_retry_offered",
        "host_denial_retry_exhausted",
        "host_denial_retry_unrecorded",
        "host_denial_grant_unconfirmed",
    ]


def _channel_enabled(policy: Mapping[str, object], channel: str) -> bool | None:
    channels = policy.get("channel_policies")
    if not isinstance(channels, list | tuple):
        return None
    for item in cast("list[object] | tuple[object, ...]", channels):
        if not isinstance(item, Mapping):
            continue
        entry = cast(Mapping[str, object], item)
        if entry.get("channel") != channel:
            continue
        enabled = entry.get("enabled")
        return enabled if type(enabled) is bool else None
    return None


def grant_from_setup(effective: object) -> GrantReadReason:
    if not isinstance(effective, Mapping):
        return "grant_unread"
    plain = cast(Mapping[str, object], effective)
    grant_state = plain.get("grant_state")
    policy = plain.get("composed_policy")
    llm_enabled = (
        _channel_enabled(cast(Mapping[str, object], policy), "llm_inference")
        if isinstance(policy, Mapping)
        else None
    )
    if grant_state not in {"granted", "missing"} or llm_enabled is None:
        return "grant_unread"
    if grant_state == "granted" and llm_enabled is True:
        return "grant_confirmed"
    return "grant_absent"


def _grant_from_control_error(error: ControlError) -> GrantReadReason:
    reason = error.reason
    if reason == "vault_locked":
        return "vault_locked"
    if reason == "privacy_projection_blocked":
        return "privacy_authority_required"
    return "service_unavailable"


async def read_repository_grant(
    connect: PrivacyConnector, *, deadline_ms: int | None = None
) -> GrantReadReason:
    # Bound connection/handshake, request, and cleanup together, not just the RPC.
    try:
        budget = GRANT_READ_DEADLINE_MS if deadline_ms is None else deadline_ms
        with anyio.fail_after(budget / 1_000):
            client = await connect(ControlClientKind.CLI)
            try:
                effective = await client.privacy_get_setup(
                    JsonObject({"schema_version": "2.0.0"}), deadline_ms=budget
                )
            finally:
                await client.close()
        return grant_from_setup(effective)
    except ControlError as error:
        return _grant_from_control_error(error)
    except Exception:
        return "service_unavailable"


def read_admission_state(workspace_locator: str | None, *, host: str = "claude") -> str:
    if workspace_locator is None:
        return "unknown"
    try:
        from finishup.cli.provider_status import host_admission_observation

        report = host_admission_observation(Path(workspace_locator))
        entry = report.get(host)
        state = entry.get("state") if isinstance(entry, Mapping) else None
    except Exception:
        return "unknown"
    return state if type(state) is str and state in ADMISSION_STATES else "unknown"


def read_host_hold_facts(
    workspace_locator: str | None,
    *,
    connect: PrivacyConnector | None,
    run_async: AsyncRunner,
    skip_service: bool = False,
) -> HostHoldFacts:
    """Read the grant through the repository-bound service and the host's admission file.

    Fail-soft to a closed unread token: a hook must never guess that the owner authorized
    review. ``connect`` is already bound to ``workspace_locator``; ``None`` without a locator
    means no repository-bound read is possible and the grant stays ``workspace_unbound``.
    """

    admission = read_admission_state(workspace_locator)
    if skip_service:
        return HostHoldFacts("service_skipped", admission)
    if workspace_locator is None:
        return HostHoldFacts("workspace_unbound", admission)
    if connect is None:
        from finishup.cli.hooks import bound_connector
        from finishup.service.client import connect_service

        connect = cast(PrivacyConnector, bound_connector(connect_service, workspace_locator))
    grant: GrantReadReason = "service_unavailable"
    try:
        outcome = run_async(lambda: read_repository_grant(connect))
    except Exception:
        outcome = None
    if type(outcome) is str and outcome in GRANT_REASONS:
        grant = cast(GrantReadReason, outcome)
    return HostHoldFacts(grant, admission)


def _retry_key(session_id: str) -> str:
    digest = hashlib.sha256(_RETRY_KEY_DOMAIN + b"claude\x00" + session_id.encode("utf-8"))
    return digest.hexdigest()


def _private_regular_file(descriptor: int) -> bool:
    facts = os.fstat(descriptor)
    return (
        stat.S_ISREG(facts.st_mode)
        and facts.st_uid == os.getuid()
        and stat.S_IMODE(facts.st_mode) == 0o600
        and facts.st_nlink == 1
    )


def _load_retry_ledger(path: Path) -> dict[str, int] | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return {}
    try:
        if not _private_regular_file(descriptor):
            return None
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(_MAX_RETRY_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_RETRY_FILE_BYTES:
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    if len(cast(dict[object, object], parsed)) > _MAX_RETRY_ENTRIES:
        return None
    ledger: dict[str, int] = {}
    for key, value in cast(dict[object, object], parsed).items():
        if (
            type(key) is not str
            or len(key) != 64
            or any(char not in "0123456789abcdef" for char in key)
            or type(value) is not int
            or value < 0
        ):
            return None
        ledger[key] = value
    return ledger


def note_retry_offer(
    session_id: str, *, _state: Path | None = None, _now_ms: int | None = None
) -> RetryOfferOutcome:
    """Durably reserve at most one retry per session, failing closed on uncertainty.

    A full or damaged ledger never forgets a prior offer. At capacity, new sessions need
    human approval. Lock contention also returns immediately without offering a retry.
    """

    if fcntl is None:
        return "unrecorded"
    root = state_dir() if _state is None else _state
    directory = root / "observation"
    path = directory / _RETRY_FILE_NAME
    lock_path = directory / _RETRY_LOCK_NAME
    key = _retry_key(session_id)
    now_ms = _now_ms if _now_ms is not None else int(time.time() * 1000)
    temporary: Path | None = None
    try:
        ensure_owner_only_dir(directory)
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        lock_descriptor = os.open(lock_path, flags, 0o600)
        try:
            if not _private_regular_file(lock_descriptor):
                return "unrecorded"
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            ledger = _load_retry_ledger(path)
            if ledger is None:
                return "unrecorded"
            if key in ledger:
                return "repeat"
            if len(ledger) >= _MAX_RETRY_ENTRIES:
                return "unrecorded"
            ledger[key] = now_ms
            encoded = json.dumps(ledger, separators=(",", ":"), sort_keys=True).encode("utf-8")
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".host-hold-retries-", dir=directory
            )
            temporary = Path(temporary_name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
            return "first"
        finally:
            os.close(lock_descriptor)
    except Exception:
        return "unrecorded"
    finally:
        if temporary is not None:
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)


def classifier_verdict_present(source: object, reason: object) -> bool:
    """Recognize the host's denial forms without echoing its untrusted reason prose.

    Current Claude omits source; older adapters supply auto_mode. Unknown sources and
    missing reasons cannot establish a classifier verdict. Keep the historical token too.
    """

    return (
        source in (None, "auto_mode")
        and type(reason) is str
        and bool(reason.strip())
        and reason not in {"no_verdict", "Classifier unavailable"}
        and not reason.startswith(
            "Auto mode could not evaluate this action and is blocking it for safety"
        )
    )


def compose_host_hold_advisory(
    facts: HostHoldFacts,
    *,
    source: object,
    reason: object,
    retry_offer: RetryOfferOutcome,
) -> HostHoldAdvisory:
    """Compose the bounded advisory for one held check from closed inputs only.

    Only a recognized classifier verdict and a durably recorded first offer permit retry.
    The explanation is user-visible; Claude's event contract carries only the retry flag
    to the model. Shipped guidance supplies the exact-request and pause rules.
    """

    held_by_rule = source in ("permission_rule", "hook")
    no_verdict = not classifier_verdict_present(source, reason)
    admission_note = _ADMISSION_NOTES.get(facts.admission_state, "")
    if held_by_rule:
        return HostHoldAdvisory(
            explanation=_RULE_HELD,
            retry=False,
            diagnostic="host_denial_retry_exhausted",
        )
    if not facts.grant_confirmed:
        note = _GRANT_ABSENT_NOTE if facts.grant == "grant_absent" else ""
        return HostHoldAdvisory(
            explanation=(_UNCONFIRMED_PREFIX.format(reason=facts.grant) + _PENDING_RULES + note),
            retry=False,
            diagnostic="host_denial_grant_unconfirmed",
        )
    if no_verdict:
        return HostHoldAdvisory(
            explanation=_CONFIRMED_PREFIX + _CONFIRMED_NO_VERDICT + _PENDING_RULES + admission_note,
            retry=False,
            diagnostic="host_denial_retry_exhausted",
        )
    if retry_offer == "first":
        return HostHoldAdvisory(
            explanation=_CONFIRMED_PREFIX + _CONFIRMED_RETRY + _PENDING_RULES + admission_note,
            retry=True,
            diagnostic="host_denial_retry_offered",
        )
    return HostHoldAdvisory(
        explanation=_CONFIRMED_PREFIX + _CONFIRMED_NO_RETRY + _PENDING_RULES + admission_note,
        retry=False,
        diagnostic=(
            "host_denial_retry_unrecorded"
            if retry_offer == "unrecorded"
            else "host_denial_retry_exhausted"
        ),
    )
