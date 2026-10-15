"""Owner-selected observation detail and bounded-capacity settings.

These values describe how much structural observation work the local writer may
retain.  They are deliberately separate from native content consent and from
the privacy/egress policy: selecting a larger observation budget never grants a
new content category, provider, credential, or network channel.

The wire helpers in this module are used only by the owner-private local
observation state.  They accept a closed vocabulary so a caller cannot smuggle
an arbitrary capture policy into a hook or workspace file.

Persisted settings keep ``capacity`` as a plain integer queue count.  A
custom count (#828) outside the three named profiles is therefore read by an
older revision as a malformed setting and dropped to the safe Focused/512
default; this revision drops any count outside the supported finite range the
same way.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Final, Literal, cast

from finishup.domain.observation_budget import (
    BUDGET_POLICY_VERSION,
    BUDGET_VALIDATION_STATUS,
    STANDARD_CAPACITY,
    CapacityProfile,
    ObservationCapacity,
    ObservationMode,
    PressureState,
)
from finishup.domain.values import JsonObject, JsonValue, Timestamp, validate_commitment
from finishup.protocol.errors import ProtocolValueError

_MAX_SESSION_OVERRIDES: Final = 256


ObservationDetailProfile = ObservationMode
ObservationCapacityProfile = CapacityProfile


_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
_MAX_STATUS_TOKEN_BYTES: Final = 128


def _is_bounded_ascii_token(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        length = len(value.encode("ascii", "strict"))
    except UnicodeEncodeError:
        return False
    return 1 <= length <= _MAX_STATUS_TOKEN_BYTES


OBSERVATION_CAPACITY_QUEUE_COUNTS: Final[dict[ObservationCapacityProfile, int]] = {
    ObservationCapacityProfile.STANDARD: int(ObservationCapacityProfile.STANDARD),
    ObservationCapacityProfile.LARGER: int(ObservationCapacityProfile.LARGER),
    ObservationCapacityProfile.LARGEST: int(ObservationCapacityProfile.LARGEST),
}


@dataclass(frozen=True, slots=True)
class ObservationSelection:
    """One closed detail/capacity pair.

    Capacity is intentionally independent from detail.  A caller may select
    Detailed with the standard queue or Focused with a larger queue; the
    admission controller still has to validate the corresponding byte and
    auxiliary-state budgets before making a selection effective.
    """

    detail: ObservationDetailProfile = ObservationDetailProfile.FOCUSED
    capacity: ObservationCapacity = STANDARD_CAPACITY

    def __post_init__(self) -> None:
        if type(self.detail) is not ObservationDetailProfile:
            raise ProtocolValueError("invalid_event_value_type")
        capacity: object = self.capacity
        if isinstance(capacity, CapacityProfile):
            # Compatibility seam: callers written against the closed profile
            # vocabulary still construct the equivalent finite capacity.
            object.__setattr__(self, "capacity", ObservationCapacity(int(capacity)))
        elif type(capacity) is not ObservationCapacity:
            raise ProtocolValueError("invalid_event_value_type")

    @property
    def queue_count(self) -> int:
        """Return the finite queue-count target of this selection."""

        return self.capacity.queue_count


DEFAULT_OBSERVATION_SELECTION: Final = ObservationSelection()


@dataclass(frozen=True, slots=True)
class ObservationSelectionSetting:
    """One owner setting stored at workspace or session scope."""

    selection: ObservationSelection
    set_at: Timestamp
    expires_at: Timestamp | None = None

    def __post_init__(self) -> None:
        if type(self.selection) is not ObservationSelection:
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.set_at) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        if self.expires_at is not None and type(self.expires_at) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        if self.expires_at is not None and self.expires_at <= self.set_at:
            raise ProtocolValueError("invalid_timestamp")

    def expired(self, now: Timestamp) -> bool:
        """Return whether this setting has reached its exclusive expiry instant."""

        if type(now) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        return self.expires_at is not None and now >= self.expires_at


@dataclass(frozen=True, slots=True)
class ObservationSelectionSettings:
    """Immutable workspace settings and bounded per-session overrides.

    The outer workspace state remains mutable for its existing event-sourced
    queues, but this value is immutable so cache copies cannot share a mutable
    settings map with a writer.  Session keys are path-free HMAC commitments.
    """

    workspace: ObservationSelectionSetting | None = None
    sessions: tuple[tuple[str, ObservationSelectionSetting], ...] = ()

    def __post_init__(self) -> None:
        if self.workspace is not None and type(self.workspace) is not ObservationSelectionSetting:
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.sessions) is not tuple or len(self.sessions) > _MAX_SESSION_OVERRIDES:
            raise ProtocolValueError("invalid_event_value_type")
        previous: str | None = None
        seen: set[str] = set()
        for item in self.sessions:
            if type(item) is not tuple or len(item) != 2:
                raise ProtocolValueError("invalid_event_value_type")
            key, setting = item
            if type(key) is not str or key in seen:
                raise ProtocolValueError("invalid_commitment")
            try:
                validate_commitment(key)
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise ProtocolValueError("invalid_commitment") from exc
            if type(setting) is not ObservationSelectionSetting:
                raise ProtocolValueError("invalid_event_value_type")
            if previous is not None and key.encode() <= previous.encode():
                raise ProtocolValueError("invalid_event_value_type")
            previous = key
            seen.add(key)

    def session(self, session_commitment: str) -> ObservationSelectionSetting | None:
        """Return one session override by its path-free commitment."""

        try:
            validate_commitment(session_commitment)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise ProtocolValueError("invalid_commitment") from exc
        for key, setting in self.sessions:
            if key == session_commitment:
                return setting
        return None

    def with_workspace(
        self, setting: ObservationSelectionSetting | None
    ) -> ObservationSelectionSettings:
        """Return settings with the persisted workspace default replaced."""

        return replace(self, workspace=setting)

    def with_session(
        self,
        session_commitment: str,
        setting: ObservationSelectionSetting,
    ) -> ObservationSelectionSettings:
        """Return settings with one bounded session override replaced."""

        try:
            validate_commitment(session_commitment)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise ProtocolValueError("invalid_commitment") from exc
        if type(setting) is not ObservationSelectionSetting:
            raise ProtocolValueError("invalid_event_value_type")
        entries = {key: value for key, value in self.sessions}
        entries[session_commitment] = setting
        if len(entries) > _MAX_SESSION_OVERRIDES:
            raise ProtocolValueError("observation_selection_session_limit")
        return replace(
            self,
            sessions=tuple(sorted(entries.items(), key=lambda item: item[0].encode())),
        )

    def without_session(self, session_commitment: str) -> ObservationSelectionSettings:
        """Return settings with one session override removed."""

        try:
            validate_commitment(session_commitment)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise ProtocolValueError("invalid_commitment") from exc
        return replace(
            self,
            sessions=tuple(
                (key, value) for key, value in self.sessions if key != session_commitment
            ),
        )

    def aggregate_capacity(
        self,
        *,
        now: Timestamp | None = None,
    ) -> ObservationCapacity:
        """Return the finite workspace ceiling implied by active settings.

        The shared queue starts from the workspace baseline: the active
        workspace setting's capacity, else the standard default.  An active
        session selection can only raise the aggregate above that baseline,
        never lower it, so a session that chose a small custom count does not
        shrink the queue its siblings share.  The result is capped by the
        supported finite range at 8,192.  Per-session fairness and byte limits
        remain admission-controller responsibilities; this helper never
        grants a sibling's detail mode.
        """

        def active(setting: ObservationSelectionSetting | None) -> bool:
            return setting is not None and (now is None or not setting.expired(now))

        workspace = self.workspace
        baseline = (
            workspace.selection.capacity
            if workspace is not None and active(workspace)
            else STANDARD_CAPACITY
        )
        raised = [setting.selection.capacity for _, setting in self.sessions if active(setting)]
        return max([baseline, *raised], key=lambda capacity: capacity.queue_count)


SelectionOrigin = Literal["session", "workspace", "configured", "default"]

EFFECTIVE_BUDGET_SCHEMA: Final = "yoetz.observation-effective-budget/1"
_EMPTY_EFFECTIVE_BUDGET: Final = JsonObject({})


@dataclass(frozen=True, slots=True)
class ObservationSelectionResolution:
    """The selected setting after scope precedence, before pressure gates."""

    selection: ObservationSelection
    origin: SelectionOrigin
    expires_at: Timestamp | None = None

    def __post_init__(self) -> None:
        if type(self.selection) is not ObservationSelection:
            raise ProtocolValueError("invalid_event_value_type")
        if self.origin not in {"session", "workspace", "configured", "default"}:
            raise ProtocolValueError("invalid_event_value_type")
        if self.expires_at is not None and type(self.expires_at) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")


@dataclass(frozen=True, slots=True)
class ObservationSelectionRuntimeStatus:
    """Typed read-only pressure projection carried by observation status.

    This snapshot reports selection and finite structural usage only.  It is
    intentionally separate from consent and privacy policy: ``content_allowed``
    is the current pressure admission result, not a content grant, and the
    accounting object contains counters/commitments without user content.
    """

    selected_mode: ObservationDetailProfile
    effective_mode: ObservationDetailProfile
    selected_capacity: ObservationCapacity
    effective_capacity: ObservationCapacity
    selection_origin: SelectionOrigin
    selection_expires_at: Timestamp | None
    pressure_state: PressureState
    pressure_transition_identity: str | None
    content_allowed: bool
    admission_allowed: bool
    queue_count: int
    queue_bytes: int
    state_bytes: int
    oldest_pending_age_ms: int
    pending_attempts: int
    pending_lifecycle_count: int
    capture_backlog: JsonObject
    protected_count_reserve: int
    protected_bytes_reserve: int
    session_fair_share: int
    session_fair_share_bytes: int
    accounting: JsonObject
    session_commitment: str | None = None
    policy_version: str = BUDGET_POLICY_VERSION
    validation_status: str = BUDGET_VALIDATION_STATUS
    # Derived from the capacities when left empty; an explicit value must
    # match.  Older snapshots (control 2.6-2.8) carry neither key.
    selected_capacity_label: str = ""
    effective_capacity_label: str = ""
    effective_budget: JsonObject = _EMPTY_EFFECTIVE_BUDGET

    def __post_init__(self) -> None:
        if type(self.selected_mode) is not ObservationDetailProfile:
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.effective_mode) is not ObservationDetailProfile:
            raise ProtocolValueError("invalid_event_value_type")
        for field_name in ("selected_capacity", "effective_capacity"):
            raw_capacity: object = getattr(self, field_name)
            if isinstance(raw_capacity, CapacityProfile):
                # Same compatibility seam as ObservationSelection.
                object.__setattr__(self, field_name, ObservationCapacity(int(raw_capacity)))
            elif type(raw_capacity) is not ObservationCapacity:
                raise ProtocolValueError("invalid_event_value_type")
        for field_name, capacity in (
            ("selected_capacity_label", self.selected_capacity),
            ("effective_capacity_label", self.effective_capacity),
        ):
            label = getattr(self, field_name)
            if label == "":
                object.__setattr__(self, field_name, capacity.label)
            elif label != capacity.label:
                raise ProtocolValueError("invalid_event_value_type")
        if type(self.effective_budget) is not JsonObject:
            raise ProtocolValueError("invalid_event_value_type")
        if self.effective_budget and (
            self.effective_budget.get("schema") != EFFECTIVE_BUDGET_SCHEMA
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.selection_origin) is not str or self.selection_origin not in {
            "session",
            "workspace",
            "configured",
            "default",
        }:
            raise ProtocolValueError("invalid_event_value_type")
        if (
            self.selection_expires_at is not None
            and type(self.selection_expires_at) is not Timestamp
        ):
            raise ProtocolValueError("invalid_timestamp")
        if type(self.pressure_state) is not PressureState:
            raise ProtocolValueError("invalid_event_value_type")
        if self.pressure_transition_identity is not None and not _is_bounded_ascii_token(
            self.pressure_transition_identity
        ):
            raise ProtocolValueError("invalid_event_value_type")
        for value in (
            self.content_allowed,
            self.admission_allowed,
        ):
            if type(value) is not bool:
                raise ProtocolValueError("invalid_event_value_type")
        for value in (
            self.queue_count,
            self.queue_bytes,
            self.state_bytes,
            self.oldest_pending_age_ms,
            self.pending_attempts,
            self.pending_lifecycle_count,
            self.protected_count_reserve,
            self.protected_bytes_reserve,
            self.session_fair_share,
            self.session_fair_share_bytes,
        ):
            if (
                type(value) is not int
                or isinstance(value, bool)
                or not 0 <= value <= _MAX_SAFE_INTEGER
            ):
                raise ProtocolValueError("invalid_event_value_type")
        if type(self.capture_backlog) is not JsonObject:
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.accounting) is not JsonObject:
            raise ProtocolValueError("invalid_event_value_type")
        if self.session_commitment is not None:
            try:
                validate_commitment(self.session_commitment)
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise ProtocolValueError("invalid_commitment") from exc
        for value in (self.policy_version, self.validation_status):
            if not _is_bounded_ascii_token(value):
                raise ProtocolValueError("invalid_event_value_type")


def observation_selection_runtime_status_to_json(
    value: ObservationSelectionRuntimeStatus,
) -> JsonObject:
    """Encode one bounded runtime snapshot for the observation status wire."""

    if type(value) is not ObservationSelectionRuntimeStatus:
        raise ProtocolValueError("invalid_event_value_type")
    return JsonObject(
        {
            "selected_mode": value.selected_mode.value,
            "effective_mode": value.effective_mode.value,
            "selected_capacity": value.selected_capacity.queue_count,
            "effective_capacity": value.effective_capacity.queue_count,
            "selected_capacity_label": value.selected_capacity_label,
            "effective_capacity_label": value.effective_capacity_label,
            "effective_budget": value.effective_budget,
            "selection_origin": value.selection_origin,
            "selection_expires_at": (
                None if value.selection_expires_at is None else value.selection_expires_at.wire
            ),
            "pressure_state": value.pressure_state.value,
            "pressure_transition_identity": value.pressure_transition_identity,
            "content_allowed": value.content_allowed,
            "admission_allowed": value.admission_allowed,
            "queue_count": value.queue_count,
            "queue_bytes": value.queue_bytes,
            "state_bytes": value.state_bytes,
            "oldest_pending_age_ms": value.oldest_pending_age_ms,
            "pending_attempts": value.pending_attempts,
            "pending_lifecycle_count": value.pending_lifecycle_count,
            "capture_backlog": value.capture_backlog,
            "protected_count_reserve": value.protected_count_reserve,
            "protected_bytes_reserve": value.protected_bytes_reserve,
            "session_fair_share": value.session_fair_share,
            "session_fair_share_bytes": value.session_fair_share_bytes,
            "accounting": value.accounting,
            "session_commitment": value.session_commitment,
            "policy_version": value.policy_version,
            "validation_status": value.validation_status,
        }
    )


def observation_selection_runtime_status_from_json(
    value: object,
) -> ObservationSelectionRuntimeStatus:
    """Decode a strict runtime snapshot from a validated local projection."""

    if not isinstance(value, Mapping):
        raise ProtocolValueError("invalid_event_value_type")
    source = cast(Mapping[str, object], value)
    required = {
        "selected_mode",
        "effective_mode",
        "selected_capacity",
        "effective_capacity",
        "selection_origin",
        "selection_expires_at",
        "pressure_state",
        "pressure_transition_identity",
        "content_allowed",
        "admission_allowed",
        "queue_count",
        "queue_bytes",
        "state_bytes",
        "oldest_pending_age_ms",
        "pending_attempts",
        "pending_lifecycle_count",
        "capture_backlog",
        "protected_count_reserve",
        "protected_bytes_reserve",
        "session_fair_share",
        "session_fair_share_bytes",
        "accounting",
        "session_commitment",
        "policy_version",
        "validation_status",
    }
    # Added by #828 (control 2.9): always emitted, optional on decode so a
    # 2.6-2.8 snapshot still decodes with derived labels and no budget record.
    optional = {"selected_capacity_label", "effective_capacity_label", "effective_budget"}
    if not required <= set(source) or set(source) - required - optional:
        raise ProtocolValueError("invalid_event_value_type")
    try:
        selected_mode = ObservationDetailProfile.from_value(source["selected_mode"])
        effective_mode = ObservationDetailProfile.from_value(source["effective_mode"])
        selected_capacity = _wire_capacity(source["selected_capacity"])
        effective_capacity = _wire_capacity(source["effective_capacity"])
        pressure_state = PressureState(source["pressure_state"])
    except (TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_event_value_type") from exc
    labels = (source.get("selected_capacity_label", ""), source.get("effective_capacity_label", ""))
    if any(type(label) is not str for label in labels):
        raise ProtocolValueError("invalid_event_value_type")
    effective_budget = source.get("effective_budget", _EMPTY_EFFECTIVE_BUDGET)
    expiry = source["selection_expires_at"]
    session_commitment = source["session_commitment"]
    try:
        expiry_stamp = None if expiry is None else Timestamp(cast(str, expiry))
    except (TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_timestamp") from exc
    return ObservationSelectionRuntimeStatus(
        selected_mode=selected_mode,
        effective_mode=effective_mode,
        selected_capacity=selected_capacity,
        effective_capacity=effective_capacity,
        selection_origin=cast(SelectionOrigin, source["selection_origin"]),
        selection_expires_at=expiry_stamp,
        pressure_state=pressure_state,
        pressure_transition_identity=cast(str | None, source["pressure_transition_identity"]),
        content_allowed=cast(bool, source["content_allowed"]),
        admission_allowed=cast(bool, source["admission_allowed"]),
        queue_count=cast(int, source["queue_count"]),
        queue_bytes=cast(int, source["queue_bytes"]),
        state_bytes=cast(int, source["state_bytes"]),
        oldest_pending_age_ms=cast(int, source["oldest_pending_age_ms"]),
        pending_attempts=cast(int, source["pending_attempts"]),
        pending_lifecycle_count=cast(int, source["pending_lifecycle_count"]),
        capture_backlog=cast(JsonObject, source["capture_backlog"]),
        protected_count_reserve=cast(int, source["protected_count_reserve"]),
        protected_bytes_reserve=cast(int, source["protected_bytes_reserve"]),
        session_fair_share=cast(int, source["session_fair_share"]),
        session_fair_share_bytes=cast(int, source["session_fair_share_bytes"]),
        accounting=cast(JsonObject, source["accounting"]),
        session_commitment=(cast(str | None, session_commitment)),
        policy_version=cast(str, source["policy_version"]),
        validation_status=cast(str, source["validation_status"]),
        selected_capacity_label=cast(str, labels[0]),
        effective_capacity_label=cast(str, labels[1]),
        effective_budget=cast(JsonObject, effective_budget),
    )


def _wire_capacity(value: object) -> ObservationCapacity:
    # An exact integer (or the historic decimal-string spelling) in the
    # supported finite range; anything else is malformed.
    return ObservationCapacity.from_value(value)


def resolve_observation_selection(
    settings: ObservationSelectionSettings,
    *,
    session_commitment: str | None = None,
    configured: ObservationSelection | None = None,
    now: Timestamp | None = None,
) -> ObservationSelectionResolution:
    """Resolve session > workspace > configured > Focused/512 precedence.

    ``now`` is optional for callers that already pruned persisted settings. If
    supplied, an expired setting is ignored without mutating the immutable
    input; the local store performs the durable removal under its lock.
    """

    if type(settings) is not ObservationSelectionSettings:
        raise ProtocolValueError("invalid_event_value_type")
    if session_commitment is not None:
        settings.session(session_commitment)
    selected_session = None if session_commitment is None else settings.session(session_commitment)
    if selected_session is not None and (now is None or not selected_session.expired(now)):
        return ObservationSelectionResolution(
            selected_session.selection,
            "session",
            selected_session.expires_at,
        )
    workspace = settings.workspace
    if workspace is not None and (now is None or not workspace.expired(now)):
        return ObservationSelectionResolution(
            workspace.selection, "workspace", workspace.expires_at
        )
    if configured is not None:
        if type(configured) is not ObservationSelection:
            raise ProtocolValueError("invalid_event_value_type")
        return ObservationSelectionResolution(configured, "configured")
    return ObservationSelectionResolution(DEFAULT_OBSERVATION_SELECTION, "default")


def _setting_to_json(setting: ObservationSelectionSetting) -> JsonObject:
    return JsonObject(
        {
            "detail": setting.selection.detail.value,
            "capacity": setting.selection.capacity.queue_count,
            "set_at": setting.set_at.wire,
            "expires_at": None if setting.expires_at is None else setting.expires_at.wire,
        }
    )


def observation_selection_settings_to_json(
    settings: ObservationSelectionSettings,
) -> JsonObject:
    """Encode settings with deterministic keys and no user content."""

    if type(settings) is not ObservationSelectionSettings:
        raise ProtocolValueError("invalid_event_value_type")
    return JsonObject(
        {
            "workspace": None
            if settings.workspace is None
            else _setting_to_json(settings.workspace),
            "sessions": JsonObject(
                {key: _setting_to_json(value) for key, value in settings.sessions}
            ),
        }
    )


def _setting_from_json(raw: object) -> ObservationSelectionSetting:
    if not isinstance(raw, Mapping):
        raise ProtocolValueError("invalid_event_value_type")
    row = cast(Mapping[str, JsonValue], raw)
    try:
        detail = ObservationDetailProfile.from_value(row.get("detail"))
        capacity = _wire_capacity(row.get("capacity"))
    except (ValueError, TypeError) as exc:
        raise ProtocolValueError("invalid_event_value_type") from exc
    set_at = row.get("set_at")
    expires_at = row.get("expires_at")
    if type(set_at) is not str:
        raise ProtocolValueError("invalid_timestamp")
    try:
        set_stamp = Timestamp(set_at)
        expiry_stamp = None if expires_at is None else Timestamp(str(expires_at))
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise ProtocolValueError("invalid_timestamp") from exc
    return ObservationSelectionSetting(
        ObservationSelection(
            detail,
            capacity,
        ),
        set_stamp,
        expiry_stamp,
    )


def observation_selection_settings_from_json(raw: object) -> ObservationSelectionSettings:
    """Decode settings, dropping malformed overrides to a safe empty state."""

    if not isinstance(raw, Mapping):
        return ObservationSelectionSettings()
    row = cast(Mapping[str, JsonValue], raw)
    workspace: ObservationSelectionSetting | None = None
    raw_workspace = row.get("workspace")
    if raw_workspace is not None:
        try:
            workspace = _setting_from_json(raw_workspace)
        except ProtocolValueError, TypeError, ValueError:
            workspace = None
    sessions: list[tuple[str, ObservationSelectionSetting]] = []
    raw_sessions = row.get("sessions")
    if isinstance(raw_sessions, Mapping):
        for key, value in sorted(
            cast(Mapping[str, JsonValue], raw_sessions).items(),
            key=lambda item: str(item[0]).encode(),
        ):
            if type(key) is not str:
                continue
            try:
                validate_commitment(key)
                setting = _setting_from_json(value)
            except ProtocolValueError, TypeError, ValueError:
                continue
            sessions.append((key, setting))
            if len(sessions) >= _MAX_SESSION_OVERRIDES:
                break
    return ObservationSelectionSettings(workspace=workspace, sessions=tuple(sessions))


__all__ = [
    "DEFAULT_OBSERVATION_SELECTION",
    "EFFECTIVE_BUDGET_SCHEMA",
    "OBSERVATION_CAPACITY_QUEUE_COUNTS",
    "ObservationCapacity",
    "ObservationCapacityProfile",
    "ObservationDetailProfile",
    "ObservationSelection",
    "ObservationSelectionResolution",
    "ObservationSelectionSetting",
    "ObservationSelectionSettings",
    "ObservationSelectionRuntimeStatus",
    "SelectionOrigin",
    "observation_selection_runtime_status_from_json",
    "observation_selection_runtime_status_to_json",
    "observation_selection_settings_from_json",
    "observation_selection_settings_to_json",
    "resolve_observation_selection",
]
