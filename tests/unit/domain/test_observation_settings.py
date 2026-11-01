"""Owner-scoped observation selection settings and persistence boundaries."""

from __future__ import annotations

from pathlib import Path

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.domain.observation_budget import (
    LARGER_CAPACITY,
    STANDARD_CAPACITY,
    ObservationCapacity,
    PressureState,
)
from finishup.domain.observation_settings import (
    DEFAULT_OBSERVATION_SELECTION,
    EFFECTIVE_BUDGET_SCHEMA,
    ObservationCapacityProfile,
    ObservationDetailProfile,
    ObservationSelection,
    ObservationSelectionRuntimeStatus,
    ObservationSelectionSetting,
    ObservationSelectionSettings,
    observation_selection_runtime_status_from_json,
    observation_selection_runtime_status_to_json,
    observation_selection_settings_from_json,
    observation_selection_settings_to_json,
    resolve_observation_selection,
)
from finishup.domain.values import JsonObject, Timestamp
from finishup.protocol.errors import ProtocolValueError

_SET = Timestamp("2026-01-01T00:00:00.000Z")
_EXPIRY = Timestamp("2026-01-02T00:00:00.000Z")
_LATER = Timestamp("2026-01-03T00:00:00.000Z")


def _selection(
    detail: ObservationDetailProfile, capacity: ObservationCapacityProfile | ObservationCapacity
) -> ObservationSelection:
    return ObservationSelection(detail, ObservationCapacity.from_value(capacity))


def test_resolution_prefers_session_then_workspace_then_default() -> None:
    workspace = ObservationSelectionSetting(
        _selection(ObservationDetailProfile.FOCUSED, ObservationCapacityProfile.LARGER),
        _SET,
    )
    session = ObservationSelectionSetting(
        _selection(ObservationDetailProfile.DETAILED, ObservationCapacityProfile.STANDARD),
        _SET,
    )
    commitment = "hmac-sha256:" + "a" * 64
    settings = ObservationSelectionSettings(workspace=workspace).with_session(commitment, session)

    resolved = resolve_observation_selection(settings, session_commitment=commitment)
    assert resolved.selection == session.selection
    assert resolved.origin == "session"
    assert resolve_observation_selection(settings).selection == workspace.selection
    assert (
        resolve_observation_selection(ObservationSelectionSettings()).selection
        == DEFAULT_OBSERVATION_SELECTION
    )


def test_settings_json_round_trip_is_closed_and_path_free() -> None:
    commitment = "hmac-sha256:" + "b" * 64
    setting = ObservationSelectionSetting(
        _selection(ObservationDetailProfile.DETAILED, ObservationCapacityProfile.LARGEST),
        _SET,
        _EXPIRY,
    )
    settings = ObservationSelectionSettings(workspace=setting).with_session(commitment, setting)

    restored = observation_selection_settings_from_json(
        observation_selection_settings_to_json(settings)
    )
    assert restored == settings
    assert all("/" not in key for key, _ in restored.sessions)


def test_malformed_settings_drop_to_safe_default() -> None:
    parsed = observation_selection_settings_from_json(
        {
            "workspace": {"detail": "detailed", "capacity": 123, "set_at": "bad"},
            "sessions": {"/private/path": {"detail": "detailed", "capacity": 8192}},
        }
    )
    assert parsed == ObservationSelectionSettings()


def test_expired_store_setting_is_removed_and_falls_back(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.set_workspace_selection(
        workspace,
        _selection(ObservationDetailProfile.DETAILED, ObservationCapacityProfile.LARGER),
        set_at=_SET,
        expires_at=_EXPIRY,
    )
    assert store.selection_settings_for(workspace, now=_LATER).workspace is None
    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.selection_settings_for(workspace, now=_LATER).workspace is None


def test_session_selection_is_cleared_on_session_end(tmp_path: Path) -> None:
    store = LocalObservationStore(_state=tmp_path)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace, granted_at=_SET)
    session = store.bind_codex_session(workspace, "session-settings")
    store.set_session_selection(
        workspace,
        session,
        _selection(ObservationDetailProfile.DETAILED, ObservationCapacityProfile.STANDARD),
        set_at=_SET,
        expires_at=_EXPIRY,
    )
    store.note_session_end(workspace, session, generation=1)
    assert store.session_selection_setting(workspace, session, now=_SET) is None


def test_expiry_must_be_after_setting_time() -> None:
    with pytest.raises(ProtocolValueError):
        ObservationSelectionSetting(
            DEFAULT_OBSERVATION_SELECTION,
            _SET,
            _SET,
        )


def test_runtime_status_round_trip_is_typed_and_path_free() -> None:
    commitment = "hmac-sha256:" + "c" * 64
    runtime = ObservationSelectionRuntimeStatus(
        selected_mode=ObservationDetailProfile.DETAILED,
        effective_mode=ObservationDetailProfile.FOCUSED,
        selected_capacity=LARGER_CAPACITY,
        effective_capacity=STANDARD_CAPACITY,
        selection_origin="session",
        selection_expires_at=_EXPIRY,
        pressure_state=PressureState.HIGH,
        pressure_transition_identity="observation-budget-v1:healthy>high:bytes:7",
        content_allowed=False,
        admission_allowed=True,
        queue_count=7,
        queue_bytes=128,
        state_bytes=256,
        oldest_pending_age_ms=10,
        pending_attempts=1,
        pending_lifecycle_count=0,
        capture_backlog=JsonObject({"count": 0}),
        protected_count_reserve=128,
        protected_bytes_reserve=131072,
        session_fair_share=128,
        session_fair_share_bytes=131072,
        accounting=JsonObject({"observed_count": 7}),
        session_commitment=commitment,
    )
    encoded = observation_selection_runtime_status_to_json(runtime)
    assert observation_selection_runtime_status_from_json(encoded) == runtime
    assert "/" not in str(encoded)
    assert encoded["selected_capacity"] == 2_048
    assert encoded["selected_capacity_label"] == "larger"
    assert encoded["effective_capacity_label"] == "standard"
    assert encoded["effective_budget"] == {}


# --- #828: custom counts persist as integers; unsupported counts drop safely ---

_BUDGET = JsonObject(
    {
        "schema": EFFECTIVE_BUDGET_SCHEMA,
        "scope": "session",
        "selected_queue_count": 1_024,
        "selected_capacity_label": "custom",
    }
)


def _runtime(**overrides: object) -> ObservationSelectionRuntimeStatus:
    values: dict[str, object] = {
        "selected_mode": ObservationDetailProfile.FOCUSED,
        "effective_mode": ObservationDetailProfile.FOCUSED,
        "selected_capacity": ObservationCapacity(1_024),
        "effective_capacity": ObservationCapacity(1_024),
        "selection_origin": "workspace",
        "selection_expires_at": None,
        "pressure_state": PressureState.HEALTHY,
        "pressure_transition_identity": None,
        "content_allowed": True,
        "admission_allowed": True,
        "queue_count": 0,
        "queue_bytes": 0,
        "state_bytes": 0,
        "oldest_pending_age_ms": 0,
        "pending_attempts": 0,
        "pending_lifecycle_count": 0,
        "capture_backlog": JsonObject({"count": 0}),
        "protected_count_reserve": 256,
        "protected_bytes_reserve": 262_144,
        "session_fair_share": 256,
        "session_fair_share_bytes": 262_144,
        "accounting": JsonObject({"observed_count": 0}),
        "effective_budget": _BUDGET,
    }
    values.update(overrides)
    return ObservationSelectionRuntimeStatus(**values)  # pyright: ignore[reportArgumentType]


def test_selection_accepts_custom_capacity_and_coerces_profiles() -> None:
    custom = ObservationSelection(ObservationDetailProfile.FOCUSED, ObservationCapacity(1_024))
    assert custom.queue_count == 1_024
    assert custom.capacity.label == "custom"
    legacy = ObservationSelection(
        ObservationDetailProfile.FOCUSED,
        ObservationCapacityProfile.LARGER,  # pyright: ignore[reportArgumentType]
    )
    assert legacy.capacity == LARGER_CAPACITY
    assert legacy == ObservationSelection(ObservationDetailProfile.FOCUSED, LARGER_CAPACITY)
    assert DEFAULT_OBSERVATION_SELECTION.capacity == STANDARD_CAPACITY
    with pytest.raises(ProtocolValueError):
        ObservationSelection(ObservationDetailProfile.FOCUSED, 1_024)  # pyright: ignore[reportArgumentType]


def test_custom_capacity_setting_round_trips_as_integer() -> None:
    commitment = "hmac-sha256:" + "d" * 64
    setting = ObservationSelectionSetting(
        _selection(ObservationDetailProfile.FOCUSED, ObservationCapacity(1_024)), _SET
    )
    settings = ObservationSelectionSettings(workspace=setting).with_session(commitment, setting)
    encoded = observation_selection_settings_to_json(settings)
    workspace_row = encoded["workspace"]
    assert isinstance(workspace_row, JsonObject)
    assert workspace_row["capacity"] == 1_024
    assert type(workspace_row["capacity"]) is int
    assert observation_selection_settings_from_json(encoded) == settings


@pytest.mark.parametrize("capacity", [63, 8_193, 16_384, 0, True, "custom", None])
def test_out_of_range_capacity_setting_drops_to_safe_default(capacity: object) -> None:
    commitment = "hmac-sha256:" + "e" * 64
    parsed = observation_selection_settings_from_json(
        {
            "workspace": {
                "detail": "detailed",
                "capacity": capacity,
                "set_at": _SET.wire,
                "expires_at": None,
            },
            "sessions": {
                commitment: {
                    "detail": "detailed",
                    "capacity": capacity,
                    "set_at": _SET.wire,
                    "expires_at": None,
                }
            },
        }
    )
    assert parsed == ObservationSelectionSettings()
    assert resolve_observation_selection(parsed).selection == DEFAULT_OBSERVATION_SELECTION


def test_aggregate_capacity_is_largest_active_count_including_custom() -> None:
    commitment = "hmac-sha256:" + "f" * 64
    workspace = ObservationSelectionSetting(
        _selection(ObservationDetailProfile.FOCUSED, ObservationCapacity(700)), _SET
    )
    session = ObservationSelectionSetting(
        _selection(ObservationDetailProfile.FOCUSED, ObservationCapacity(1_500)),
        _SET,
        _EXPIRY,
    )
    settings = ObservationSelectionSettings(workspace=workspace).with_session(commitment, session)
    assert settings.aggregate_capacity(now=_SET) == ObservationCapacity(1_500)
    assert settings.aggregate_capacity(now=_LATER) == ObservationCapacity(700)
    assert ObservationSelectionSettings().aggregate_capacity() == STANDARD_CAPACITY
    lowered = ObservationSelectionSettings(
        workspace=ObservationSelectionSetting(
            _selection(ObservationDetailProfile.FOCUSED, ObservationCapacity(64)), _SET
        )
    )
    assert lowered.aggregate_capacity() == ObservationCapacity(64)


def test_aggregate_capacity_session_cannot_lower_workspace_baseline() -> None:
    commitment = "hmac-sha256:" + "e" * 64
    small_session = ObservationSelectionSetting(
        _selection(ObservationDetailProfile.FOCUSED, ObservationCapacity(64)), _SET
    )
    lone = ObservationSelectionSettings().with_session(commitment, small_session)
    assert lone.aggregate_capacity(now=_SET) == STANDARD_CAPACITY

    workspace = ObservationSelectionSetting(
        _selection(ObservationDetailProfile.FOCUSED, ObservationCapacity(128)), _SET
    )
    with_workspace = ObservationSelectionSettings(workspace=workspace).with_session(
        commitment, small_session
    )
    assert with_workspace.aggregate_capacity(now=_SET) == ObservationCapacity(128)

    expired_workspace = ObservationSelectionSettings(
        workspace=ObservationSelectionSetting(
            _selection(ObservationDetailProfile.FOCUSED, ObservationCapacity(128)),
            _SET,
            _EXPIRY,
        )
    ).with_session(commitment, small_session)
    assert expired_workspace.aggregate_capacity(now=_LATER) == STANDARD_CAPACITY


def test_runtime_status_custom_capacity_round_trips_with_labels_and_budget() -> None:
    runtime = _runtime()
    assert runtime.selected_capacity_label == "custom"
    encoded = observation_selection_runtime_status_to_json(runtime)
    assert encoded["selected_capacity"] == 1_024
    assert encoded["effective_capacity_label"] == "custom"
    assert encoded["effective_budget"] == _BUDGET
    assert observation_selection_runtime_status_from_json(encoded) == runtime


def test_runtime_status_decodes_pre_29_snapshot_without_new_keys() -> None:
    encoded = observation_selection_runtime_status_to_json(
        _runtime(
            selected_capacity=LARGER_CAPACITY,
            effective_capacity=LARGER_CAPACITY,
            effective_budget=JsonObject({}),
        )
    )
    legacy = {
        key: value
        for key, value in encoded.items()
        if key not in {"selected_capacity_label", "effective_capacity_label", "effective_budget"}
    }
    decoded = observation_selection_runtime_status_from_json(legacy)
    assert decoded.selected_capacity_label == "larger"
    assert decoded.effective_budget == JsonObject({})


@pytest.mark.parametrize(
    "mutation",
    [
        {"selected_capacity_label": "larger"},
        {"effective_capacity_label": "unlimited"},
        {"selected_capacity": 9_000},
        {"selected_capacity": 32},
        {"effective_budget": JsonObject({"schema": "other/1"})},
        {"unexpected": 1},
    ],
)
def test_runtime_status_rejects_inconsistent_capacity_fields(mutation: dict[str, object]) -> None:
    encoded: dict[str, object] = dict(observation_selection_runtime_status_to_json(_runtime()))
    encoded.update(mutation)
    with pytest.raises(ProtocolValueError):
        observation_selection_runtime_status_from_json(encoded)
