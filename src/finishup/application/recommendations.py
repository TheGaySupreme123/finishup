"""Durable, owner-controlled recommended-default advisories.

Recommendations are advice, not authority. Evaluation may add a bounded pending id, but only an
explicit CLI acceptance is allowed to apply a change. Global declines are durable by id; Codex
activation decisions are durable only for the exact target and activation digest that was shown.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Awaitable, Callable, Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal, cast

from packaging.version import Version

from finishup.application.package_update import (
    PackageUpdateAdvisory,
    build_package_update_advisory,
    installed_package_version,
    resolve_package_update_advisory,
)
from finishup.config.paths import PathSafetyError, ensure_owner_only_dir, state_dir
from finishup.domain.privacy import PrivacyPolicy

__all__ = [
    "RECOMMENDED_DEFAULTS",
    "RecommendationContext",
    "RecommendationDecision",
    "RecommendationState",
    "RecommendationStoreError",
    "RecommendationTarget",
    "RecommendedDefault",
    "cached_pending_recommendations",
    "codex_activation_recommendation_target",
    "decline_cached_recommendation",
    "evaluate_recommendation_context",
    "load_recommendation_state",
    "recommendation_by_id",
    "record_recommendation_decision",
    "refresh_pending",
    "store_recommendation_state",
]

type RecommendationKind = Literal["config_flip", "activation", "package_update"]
type RecommendationDecisionValue = Literal["accepted", "declined"]
type RecommendationContextFactory = Callable[[], Awaitable["RecommendationContext"]]

_SCHEMA: Final = "yoetz.recommendations/3"
_TARGET_SCHEMA: Final = "yoetz.recommendations/2"
_LEGACY_SCHEMA: Final = "yoetz.recommendations/1"
_STORE_NAME: Final = "recommendations.json"
_LOCK_NAME: Final = "recommendations.lock"
_MAX_STORE_BYTES: Final = 32 * 1024
_MAX_DECISIONS: Final = 32
_MAX_ACCEPTED_ACTIVATION_HISTORY: Final = 8
_MAX_DECLINED_ACTIVATION_HISTORY: Final = 16
_MAX_TEXT_LENGTH: Final = 256
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$", re.ASCII)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)


class RecommendationStoreError(Exception):
    """A bounded failure reading or durably writing recommendation decisions."""

    reason_code: str

    def __init__(self, reason_code: str) -> None:
        if reason_code not in {
            "recommendation_store_corrupt",
            "recommendation_store_unsafe",
            "recommendation_store_write_failed",
        }:
            raise ValueError("recommendation_store_reason_invalid")
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class RecommendationContext:
    """Already-resolved facts used by the pure recommendation registry."""

    observation_enabled: bool | None = None
    codex_activation_state: str | None = None
    codex_activation_target: RecommendationTarget | None = None
    package_update: PackageUpdateAdvisory | None = None


@dataclass(frozen=True, slots=True)
class RecommendedDefault:
    id: str
    introduced_in: str
    title: str
    summary: str
    kind: RecommendationKind
    is_satisfied: Callable[[RecommendationContext], bool] = field(repr=False, compare=False)
    release_version: str | None = None

    def __post_init__(self) -> None:
        if _ID.fullmatch(self.id) is None:
            raise ValueError("recommendation_id_invalid")
        for value in (self.introduced_in, self.title, self.summary):
            if type(value) is not str or not value or len(value) > _MAX_TEXT_LENGTH:
                raise ValueError("recommendation_text_invalid")


@dataclass(frozen=True, slots=True)
class RecommendationDecision:
    decision: RecommendationDecisionValue
    decided_at: datetime
    version: str
    recommendation_id: str = ""
    target: RecommendationTarget | None = None
    release_version: str | None = None


@dataclass(frozen=True, slots=True)
class RecommendationTarget:
    """Digest-only identity for one exact Codex activation decision target."""

    target_digest: str
    executable_path_digest: str
    executable_digest: str
    codex_version: str
    codex_home_digest: str
    activation_preview_digest: str
    plugin_install_digest: str

    def __post_init__(self) -> None:
        for value in (
            self.target_digest,
            self.executable_path_digest,
            self.executable_digest,
            self.codex_home_digest,
            self.activation_preview_digest,
            self.plugin_install_digest,
        ):
            if type(value) is not str or _DIGEST.fullmatch(value) is None:
                raise ValueError("recommendation_target_digest_invalid")
        if (
            type(self.codex_version) is not str
            or not self.codex_version
            or len(self.codex_version) > _MAX_TEXT_LENGTH
        ):
            raise ValueError("recommendation_target_version_invalid")
        identity_fields = {
            "activation_preview_digest": self.activation_preview_digest,
            "codex_home_digest": self.codex_home_digest,
            "codex_version": self.codex_version,
            "executable_digest": self.executable_digest,
            "executable_path_digest": self.executable_path_digest,
            "plugin_install_digest": self.plugin_install_digest,
        }
        if self.target_digest != _sha_text(
            json.dumps(identity_fields, separators=(",", ":"), sort_keys=True)
        ):
            raise ValueError("recommendation_target_identity_mismatch")


@dataclass(frozen=True, slots=True)
class RecommendationState:
    schema: str = _SCHEMA
    last_evaluated_version: str | None = None
    decisions: Mapping[str, RecommendationDecision] = field(
        default_factory=lambda: MappingProxyType({})
    )
    pending: tuple[str, ...] = ()
    pending_package_version: str | None = None
    pending_targets: Mapping[str, RecommendationTarget] = field(
        default_factory=lambda: MappingProxyType({})
    )


def _sha_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def codex_activation_recommendation_target(
    *,
    executable_path: Path | str,
    executable_digest: str,
    codex_version: str,
    codex_home: Path | str,
    activation_preview_digest: str,
    plugin_install_digest: str,
) -> RecommendationTarget:
    """Bind advice to exact target bytes without persisting either absolute path."""

    resolved_executable = os.fspath(Path(executable_path).resolve(strict=True))
    resolved_home = os.fspath(Path(codex_home).resolve(strict=False))
    fields = {
        "activation_preview_digest": activation_preview_digest,
        "codex_home_digest": _sha_text(resolved_home),
        "codex_version": codex_version,
        "executable_digest": executable_digest,
        "executable_path_digest": _sha_text(resolved_executable),
        "plugin_install_digest": plugin_install_digest,
    }
    target_digest = _sha_text(json.dumps(fields, separators=(",", ":"), sort_keys=True))
    return RecommendationTarget(target_digest=target_digest, **fields)


def _observation_satisfied(context: RecommendationContext) -> bool:
    # Unknown consumers fail conservatively: absence of a bound config reader never creates
    # advice that cannot be justified from a current value.
    return context.observation_enabled is not False


def _activation_satisfied(context: RecommendationContext) -> bool:
    # Acceptance is a recorded decision, not proof that activation still holds. Only an exact,
    # currently previewable installed-not-activated target is actionable advice. Active targets
    # need nothing; foreign/modified/ambiguous targets require manual review, not a stale prompt.
    return (
        context.codex_activation_state is None
        or context.codex_activation_state != "installed_not_activated"
        or context.codex_activation_target is None
    )


def _package_update_satisfied(context: RecommendationContext) -> bool:
    advisory = context.package_update
    return advisory is None or not advisory.is_newer


RECOMMENDED_DEFAULTS: Final[tuple[RecommendedDefault, ...]] = (
    RecommendedDefault(
        id="observation-enabled",
        introduced_in="0.1.0",
        title="Enable local observation",
        summary="Enable the local observation pipeline; workspace consent remains required.",
        kind="config_flip",
        is_satisfied=_observation_satisfied,
    ),
    RecommendedDefault(
        id="codex-plugin-activation",
        introduced_in="0.1.0",
        title="Activate the FinishUP Codex plugin",
        summary="Register and enable the installed FinishUP plugin after an exact preview.",
        kind="activation",
        is_satisfied=_activation_satisfied,
    ),
    RecommendedDefault(
        id="package-update",
        introduced_in="0.1.0",
        title="Update FinishUP",
        summary="Upgrade to the newer PyPI release reported by the policy-gated update check.",
        kind="package_update",
        is_satisfied=_package_update_satisfied,
    ),
)
_BY_ID: Final = MappingProxyType({item.id: item for item in RECOMMENDED_DEFAULTS})


def recommendation_by_id(recommendation_id: str) -> RecommendedDefault | None:
    if type(recommendation_id) is not str:
        return None
    return _BY_ID.get(recommendation_id)


def _store_path(root: Path | None) -> Path:
    return (state_dir() if root is None else root) / _STORE_NAME


def _empty_state() -> RecommendationState:
    return RecommendationState()


def _parse_timestamp(raw: object) -> datetime:
    if type(raw) is not str or not raw or len(raw) > 64:
        raise ValueError("timestamp_invalid")
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp_naive")
    return parsed.astimezone(UTC)


def _target_payload(target: RecommendationTarget) -> dict[str, str]:
    return {
        "target_digest": target.target_digest,
        "executable_path_digest": target.executable_path_digest,
        "executable_digest": target.executable_digest,
        "codex_version": target.codex_version,
        "codex_home_digest": target.codex_home_digest,
        "activation_preview_digest": target.activation_preview_digest,
        "plugin_install_digest": target.plugin_install_digest,
    }


def _parse_target(raw: object) -> RecommendationTarget:
    if type(raw) is not dict:
        raise ValueError("recommendation_target_invalid")
    row = cast(dict[str, object], raw)
    expected = {
        "target_digest",
        "executable_path_digest",
        "executable_digest",
        "codex_version",
        "codex_home_digest",
        "activation_preview_digest",
        "plugin_install_digest",
    }
    if set(row) != expected or any(type(row[name]) is not str for name in expected):
        raise ValueError("recommendation_target_invalid")
    return RecommendationTarget(
        target_digest=cast(str, row["target_digest"]),
        executable_path_digest=cast(str, row["executable_path_digest"]),
        executable_digest=cast(str, row["executable_digest"]),
        codex_version=cast(str, row["codex_version"]),
        codex_home_digest=cast(str, row["codex_home_digest"]),
        activation_preview_digest=cast(str, row["activation_preview_digest"]),
        plugin_install_digest=cast(str, row["plugin_install_digest"]),
    )


def _decision_key(recommendation_id: str, target: RecommendationTarget | None) -> str:
    if target is None:
        return recommendation_id
    return f"{recommendation_id}@{target.target_digest.removeprefix('sha256:')}"


def _release_version(value: object) -> str | None:
    # Values appear in hook command arguments; admit only bounded version tokens, never shell text.
    if value is None:
        return None
    if type(value) is not str or re.fullmatch(r"[0-9][a-zA-Z0-9.!+_-]{0,127}", value) is None:
        raise ValueError("recommendation_release_invalid")
    Version(value)
    return value


def _parse_state(parsed: object) -> RecommendationState:
    if type(parsed) is not dict:
        raise ValueError("document_invalid")
    document = cast(dict[str, object], parsed)
    schema = document.get("schema")
    expected_keys = (
        {"schema", "last_evaluated_version", "decisions", "pending"}
        if schema == _LEGACY_SCHEMA
        else {
            "schema",
            "last_evaluated_version",
            "decisions",
            "pending",
            "pending_targets",
        }
    )
    if schema == _SCHEMA:
        expected_keys.add("pending_package_version")
    if set(document) != expected_keys:
        raise ValueError("document_keys_invalid")
    if schema not in {_SCHEMA, _TARGET_SCHEMA, _LEGACY_SCHEMA}:
        raise ValueError("schema_invalid")
    version = document["last_evaluated_version"]
    if version is not None and (
        type(version) is not str or not version or len(version) > _MAX_TEXT_LENGTH
    ):
        raise ValueError("version_invalid")
    raw_decisions = document["decisions"]
    if type(raw_decisions) is not dict:
        raise ValueError("decisions_invalid")
    decision_rows = cast(dict[object, object], raw_decisions)
    if len(decision_rows) > _MAX_DECISIONS:
        raise ValueError("decisions_invalid")
    decisions: dict[str, RecommendationDecision] = {}
    for key, raw in decision_rows.items():
        if type(key) is not str or type(raw) is not dict:
            raise ValueError("decision_invalid")
        row = cast(dict[str, object], raw)
        row_keys = (
            {"decision", "decided_at", "version"}
            if schema == _LEGACY_SCHEMA
            else {"decision", "decided_at", "version", "recommendation_id", "target"}
        )
        if schema == _SCHEMA:
            row_keys.add("release_version")
        if set(row) != row_keys:
            raise ValueError("decision_keys_invalid")
        decision = row["decision"]
        decided_version = row["version"]
        if decision not in {"accepted", "declined"}:
            raise ValueError("decision_value_invalid")
        if (
            type(decided_version) is not str
            or not decided_version
            or len(decided_version) > _MAX_TEXT_LENGTH
        ):
            raise ValueError("decision_version_invalid")
        if schema == _LEGACY_SCHEMA:
            recommendation_id = key
            target = None
        else:
            recommendation_id = row["recommendation_id"]
            if type(recommendation_id) is not str or recommendation_id not in _BY_ID:
                raise ValueError("decision_recommendation_invalid")
            target = None if row["target"] is None else _parse_target(row["target"])
        if recommendation_id not in _BY_ID:
            raise ValueError("decision_recommendation_invalid")
        if target is not None and recommendation_id != "codex-plugin-activation":
            raise ValueError("decision_target_invalid")
        if key != _decision_key(recommendation_id, target):
            raise ValueError("decision_key_invalid")
        release_version = _release_version(row.get("release_version"))
        if release_version is not None and recommendation_id != "package-update":
            raise ValueError("decision_release_invalid")
        decisions[key] = RecommendationDecision(
            decision=cast(RecommendationDecisionValue, decision),
            decided_at=_parse_timestamp(row["decided_at"]),
            version=decided_version,
            recommendation_id=recommendation_id,
            target=target,
            release_version=release_version,
        )
    raw_pending = document["pending"]
    if type(raw_pending) is not list:
        raise ValueError("pending_invalid")
    pending_rows = cast(list[object], raw_pending)
    if len(pending_rows) > len(RECOMMENDED_DEFAULTS):
        raise ValueError("pending_invalid")
    pending: list[str] = []
    for item in pending_rows:
        if type(item) is not str or item not in _BY_ID or item in pending:
            raise ValueError("pending_item_invalid")
        # V1 could not say which executable/home/digest activation advice belonged to. Do not
        # advertise an un-actionable accept/decline command; an exact CLI list rebuilds it.
        if schema == _LEGACY_SCHEMA and item == "codex-plugin-activation":
            continue
        pending.append(item)
    pending_targets: dict[str, RecommendationTarget] = {}
    if schema in {_SCHEMA, _TARGET_SCHEMA}:
        raw_targets = document["pending_targets"]
        if type(raw_targets) is not dict:
            raise ValueError("pending_targets_invalid")
        for key, raw in cast(dict[object, object], raw_targets).items():
            if key != "codex-plugin-activation" or key not in pending:
                raise ValueError("pending_target_key_invalid")
            pending_targets[cast(str, key)] = _parse_target(raw)
    pending_package_version = _release_version(document.get("pending_package_version"))
    if pending_package_version is not None and "package-update" not in pending:
        raise ValueError("pending_release_invalid")
    return RecommendationState(
        pending_package_version=pending_package_version,
        last_evaluated_version=version,
        decisions=MappingProxyType(decisions),
        pending=tuple(pending),
        pending_targets=MappingProxyType(pending_targets),
    )


def load_recommendation_state(*, root: Path | None = None) -> RecommendationState:
    """Load the strict bounded state; missing is empty and corruption is never overwritten."""

    path = _store_path(root)
    if path.parent.exists():
        try:
            ensure_owner_only_dir(path.parent)
        except PathSafetyError as exc:
            raise RecommendationStoreError("recommendation_store_unsafe") from exc
    try:
        facts = path.lstat()
        if (
            stat.S_ISLNK(facts.st_mode)
            or not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
        ):
            raise RecommendationStoreError("recommendation_store_unsafe")
        raw = path.read_bytes()
    except FileNotFoundError:
        return _empty_state()
    except RecommendationStoreError:
        raise
    except OSError as exc:
        raise RecommendationStoreError("recommendation_store_unsafe") from exc
    if not raw or len(raw) > _MAX_STORE_BYTES:
        raise RecommendationStoreError("recommendation_store_corrupt")
    try:
        return _parse_state(json.loads(raw.decode("utf-8")))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise RecommendationStoreError("recommendation_store_corrupt") from exc


@contextmanager
def _state_lock(root: Path | None) -> Generator[None]:
    """Serialize recommendation read-modify-write transitions across local processes."""

    lock_path = _store_path(root).with_name(_LOCK_NAME)
    descriptor: int | None = None
    try:
        ensure_owner_only_dir(lock_path.parent)
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_uid != os.geteuid()
            or stat.S_IMODE(facts.st_mode) & 0o077
        ):
            raise RecommendationStoreError("recommendation_store_unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    except RecommendationStoreError:
        raise
    except PathSafetyError as exc:
        raise RecommendationStoreError("recommendation_store_unsafe") from exc
    except OSError as exc:
        raise RecommendationStoreError("recommendation_store_unsafe") from exc
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _timestamp_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("recommendation_decision_time_naive")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _state_payload(state: RecommendationState) -> bytes:
    if state.schema != _SCHEMA or len(state.decisions) > _MAX_DECISIONS:
        raise RecommendationStoreError("recommendation_store_write_failed")
    if (
        any(item not in _BY_ID for item in state.pending)
        or len(set(state.pending)) != len(state.pending)
        or set(state.pending_targets) - set(state.pending)
        or set(state.pending_targets) - {"codex-plugin-activation"}
        or (state.pending_package_version is not None and "package-update" not in state.pending)
    ):
        raise RecommendationStoreError("recommendation_store_write_failed")
    for key, row in state.decisions.items():
        recommendation_id = row.recommendation_id or key
        if (
            recommendation_id not in _BY_ID
            or (row.target is not None and recommendation_id != "codex-plugin-activation")
            or (row.release_version is not None and recommendation_id != "package-update")
            or key != _decision_key(recommendation_id, row.target)
        ):
            raise RecommendationStoreError("recommendation_store_write_failed")
    document = {
        "schema": state.schema,
        "last_evaluated_version": state.last_evaluated_version,
        "decisions": {
            key: {
                "decision": row.decision,
                "decided_at": _timestamp_text(row.decided_at),
                "version": row.version,
                "release_version": _release_version(row.release_version),
                "recommendation_id": row.recommendation_id or key,
                "target": None if row.target is None else _target_payload(row.target),
            }
            for key, row in sorted(state.decisions.items())
        },
        "pending_package_version": _release_version(state.pending_package_version),
        "pending": list(state.pending),
        "pending_targets": {
            key: _target_payload(target) for key, target in sorted(state.pending_targets.items())
        },
    }
    payload = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > _MAX_STORE_BYTES:
        raise RecommendationStoreError("recommendation_store_write_failed")
    return payload


def store_recommendation_state(state: RecommendationState, *, root: Path | None = None) -> Path:
    """Atomically persist owner-only recommendation state."""

    if type(state) is not RecommendationState:
        raise TypeError("recommendation_state_wrong_type")
    path = _store_path(root)
    payload = _state_payload(state)
    try:
        ensure_owner_only_dir(path.parent)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".finishup-recommendations-", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    except PathSafetyError as exc:
        raise RecommendationStoreError("recommendation_store_unsafe") from exc
    except OSError as exc:
        raise RecommendationStoreError("recommendation_store_write_failed") from exc
    return path


async def evaluate_recommendation_context(
    *,
    observation_enabled: bool | None = None,
    codex_activation_state: str | None = None,
    codex_activation_target: RecommendationTarget | None = None,
    policy: PrivacyPolicy | None = None,
    network_egress_permitted: bool | None = None,
    update_checks_enabled: bool | None = None,
    allow_network: bool = True,
    cache_root: Path | None = None,
) -> RecommendationContext:
    """Resolve the existing package advisory and combine dependency-injected local facts."""

    advisory_kwargs: dict[str, object] = {}
    if cache_root is not None:
        advisory_kwargs["cache_root"] = cache_root
    package_update = await resolve_package_update_advisory(
        policy=policy,
        network_egress_permitted=network_egress_permitted,
        update_checks_enabled=update_checks_enabled,
        allow_network=allow_network,
        **advisory_kwargs,  # type: ignore[arg-type]
    )
    return RecommendationContext(
        observation_enabled=observation_enabled,
        codex_activation_state=codex_activation_state,
        codex_activation_target=codex_activation_target,
        package_update=package_update,
    )


def _decision_suppresses(
    recommendation_id: str,
    decision: RecommendationDecision | None,
    *,
    installed_version: str,
    release_version: str | None = None,
) -> bool:
    if decision is None:
        return False
    if recommendation_id == "package-update" and decision.release_version is not None:
        return decision.release_version == release_version
    # Preserve legacy global declines: those users were promised a permanent opt-out.
    if decision.decision == "declined":
        return True
    if recommendation_id == "codex-plugin-activation":
        # Re-inspection, not historical acceptance, decides whether activation advice is needed.
        # A currently inactive target must always receive recovery, even if it returns to the exact
        # pre-apply digest that an older acceptance recorded.
        return False
    # Acceptance authorizes one exact action. Suppress it for this running version so a package
    # upgrade command does not immediately re-nag; a new release frontier is evaluated afresh.
    return decision.version == installed_version


def _compact_activation_decisions(
    decisions: dict[str, RecommendationDecision], *, current_key: str
) -> None:
    """Bound advisory history without ever discarding the decision just recorded."""

    for value, limit in (
        ("accepted", _MAX_ACCEPTED_ACTIVATION_HISTORY),
        ("declined", _MAX_DECLINED_ACTIVATION_HISTORY),
    ):
        history = sorted(
            (
                (candidate_key, row)
                for candidate_key, row in decisions.items()
                if row.recommendation_id == "codex-plugin-activation" and row.decision == value
            ),
            key=lambda item: (item[0] == current_key, item[1].decided_at, item[0]),
            reverse=True,
        )
        for stale_key, _row in history[limit:]:
            del decisions[stale_key]


def _fact_is_known(item: RecommendedDefault, context: RecommendationContext) -> bool:
    if item.id == "observation-enabled":
        return context.observation_enabled is not None
    if item.id == "codex-plugin-activation":
        return context.codex_activation_state is not None
    if item.id == "package-update":
        # A "skipped_*" advisory records that no version comparison was actually performed
        # (no policy/network authority, no cached or network answer, unparsable versions).
        # That is the absence of a fact, not a satisfied fact: a policy-less touchpoint such
        # as the plain CLI must retain daemon-established pending advice, never erase it.
        advisory = context.package_update
        return advisory is not None and advisory.outcome in {"newer_available", "up_to_date"}
    return False


async def refresh_pending(
    *,
    context: RecommendationContext | None = None,
    context_factory: RecommendationContextFactory | None = None,
    root: Path | None = None,
    version: str | None = None,
    force: bool = False,
) -> RecommendationState:
    """Recompute at a release frontier or while pending advice still needs reconciliation."""

    if context is not None and context_factory is not None:
        raise ValueError("recommendation_context_ambiguous")
    current_version = installed_package_version() if version is None else version
    if type(current_version) is not str or not current_version:
        raise ValueError("recommendation_version_invalid")
    snapshot = load_recommendation_state(root=root)
    if (
        snapshot.last_evaluated_version == current_version
        and not snapshot.pending
        and not force
        and context is None
    ):
        return snapshot
    resolved = (
        await context_factory()
        if context_factory is not None
        else (context if context is not None else RecommendationContext())
    )
    with _state_lock(root):
        current = load_recommendation_state(root=root)
        advisory = resolved.package_update
        if advisory is not None and advisory.outcome in {"newer_available", "up_to_date"}:
            # Context resolution happens outside the lock. A slower earlier result must not
            # regress a newer pending release or resurrect an older release after a decision.
            decision = current.decisions.get("package-update")
            candidates = [
                value
                for value in (
                    current.pending_package_version,
                    None if decision is None else decision.release_version,
                    _release_version(advisory.latest_version),
                )
                if value is not None
            ]
            if candidates:
                advisory = build_package_update_advisory(
                    installed_version=advisory.installed_version,
                    latest_version=max(candidates, key=Version),
                    source=advisory.source,
                )
                resolved = replace(resolved, package_update=advisory)
        release_version = (
            _release_version(advisory.latest_version)
            if advisory is not None and advisory.is_newer
            else current.pending_package_version
        )
        pending_ids: list[str] = []
        pending_targets: dict[str, RecommendationTarget] = {}
        for item in RECOMMENDED_DEFAULTS:
            target = (
                resolved.codex_activation_target if item.id == "codex-plugin-activation" else None
            )
            if _decision_suppresses(
                item.id,
                current.decisions.get(_decision_key(item.id, target)),
                installed_version=current_version,
                release_version=release_version,
            ):
                continue
            if not _fact_is_known(item, resolved):
                # An authority-limited heavy touchpoint (for example the daemon,
                # which does not own an exact selected Codex home) must not erase
                # a recommendation established by an earlier exact evaluation.
                if item.id in current.pending:
                    pending_ids.append(item.id)
                    if (retained := current.pending_targets.get(item.id)) is not None:
                        pending_targets[item.id] = retained
                continue
            if not item.is_satisfied(resolved):
                pending_ids.append(item.id)
                if target is not None:
                    pending_targets[item.id] = target
        pending = tuple(pending_ids)
        updated = RecommendationState(
            last_evaluated_version=current_version,
            decisions=current.decisions,
            pending=pending,
            pending_package_version=release_version if "package-update" in pending else None,
            pending_targets=MappingProxyType(pending_targets),
        )
        store_recommendation_state(updated, root=root)
        return updated


def _decision_release(
    state: RecommendationState, recommendation_id: str, requested: str | None
) -> str | None:
    if requested is not None and (
        recommendation_id != "package-update" or requested != state.pending_package_version
    ):
        raise ValueError("recommendation_release_changed")
    return state.pending_package_version if recommendation_id == "package-update" else None


def record_recommendation_decision(
    recommendation_id: str,
    decision: RecommendationDecisionValue,
    *,
    root: Path | None = None,
    version: str | None = None,
    now: datetime | None = None,
    target: RecommendationTarget | None = None,
    release_version: str | None = None,
) -> RecommendationState:
    """Record an explicit accept/decline and remove it from cached pending advice."""

    if recommendation_id not in _BY_ID:
        raise ValueError("recommendation_unknown")
    if decision not in {"accepted", "declined"}:
        raise ValueError("recommendation_decision_invalid")
    if (target is not None) != (recommendation_id == "codex-plugin-activation"):
        raise ValueError("recommendation_target_required")
    current_version = installed_package_version() if version is None else version
    if type(current_version) is not str or not current_version:
        raise ValueError("recommendation_version_invalid")
    with _state_lock(root):
        current = load_recommendation_state(root=root)
        selected_release = _decision_release(current, recommendation_id, release_version)
        decisions = dict(current.decisions)
        key = _decision_key(recommendation_id, target)
        decisions[key] = RecommendationDecision(
            decision=decision,
            decided_at=now if now is not None else datetime.now(tz=UTC),
            version=current_version,
            recommendation_id=recommendation_id,
            target=target,
            release_version=selected_release,
        )
        if recommendation_id == "codex-plugin-activation":
            _compact_activation_decisions(decisions, current_key=key)
        if len(decisions) > _MAX_DECISIONS:
            raise RecommendationStoreError("recommendation_store_write_failed")
        updated = RecommendationState(
            last_evaluated_version=current.last_evaluated_version or current_version,
            decisions=MappingProxyType(decisions),
            pending=tuple(item for item in current.pending if item != recommendation_id),
            pending_package_version=(
                None if recommendation_id == "package-update" else current.pending_package_version
            ),
            pending_targets=MappingProxyType(
                {
                    key: value
                    for key, value in current.pending_targets.items()
                    if key != recommendation_id
                }
            ),
        )
        store_recommendation_state(updated, root=root)
        return updated


def decline_cached_recommendation(
    recommendation_id: str,
    *,
    root: Path | None = None,
    version: str | None = None,
    now: datetime | None = None,
    release_version: str | None = None,
) -> RecommendationState:
    """Durably decline one cached pending recommendation without re-evaluating any facts.

    Decline grants nothing, so it needs no per-kind authority or network posture and must never
    route through context evaluation. Codex advice binds the cached digest-only target; global
    advice binds its stable id. Verification and the durable write share one lock transition.
    """

    if recommendation_id not in _BY_ID:
        raise ValueError("recommendation_unknown")
    current_version = installed_package_version() if version is None else version
    if type(current_version) is not str or not current_version:
        raise ValueError("recommendation_version_invalid")
    with _state_lock(root):
        current = load_recommendation_state(root=root)
        if recommendation_id not in current.pending:
            raise ValueError("recommendation_not_pending")
        target = current.pending_targets.get(recommendation_id)
        if recommendation_id == "codex-plugin-activation" and target is None:
            raise ValueError("recommendation_target_unknown")
        selected_release = _decision_release(current, recommendation_id, release_version)
        decisions = dict(current.decisions)
        key = _decision_key(recommendation_id, target)
        decisions[key] = RecommendationDecision(
            decision="declined",
            decided_at=now if now is not None else datetime.now(tz=UTC),
            version=current_version,
            recommendation_id=recommendation_id,
            target=target,
            release_version=selected_release,
        )
        if recommendation_id == "codex-plugin-activation":
            _compact_activation_decisions(decisions, current_key=key)
        updated = RecommendationState(
            last_evaluated_version=current.last_evaluated_version or current_version,
            decisions=MappingProxyType(decisions),
            pending=tuple(item for item in current.pending if item != recommendation_id),
            pending_package_version=(
                None if recommendation_id == "package-update" else current.pending_package_version
            ),
            pending_targets=MappingProxyType(
                {
                    key: value
                    for key, value in current.pending_targets.items()
                    if key != recommendation_id
                }
            ),
        )
        store_recommendation_state(updated, root=root)
        return updated


def cached_pending_recommendations(
    *, root: Path | None = None, limit: int | None = None
) -> tuple[RecommendedDefault, ...]:
    """Read cached advice only; hook callers may exception-suppress this small-file operation."""

    if limit is not None and (type(limit) is not int or limit < 0):
        raise ValueError("recommendation_limit_invalid")
    state = load_recommendation_state(root=root)
    pending = tuple(
        replace(
            _BY_ID[item],
            title=f"Update FinishUP to {state.pending_package_version}",
            release_version=state.pending_package_version,
        )
        if item == "package-update" and state.pending_package_version is not None
        else _BY_ID[item]
        for item in state.pending
    )
    return pending if limit is None else pending[:limit]
